use actix_files::{NamedFile, Files};
use actix_cors::Cors;
use actix_multipart::Multipart;
use actix_web::{web, App, HttpServer, Responder, HttpResponse, Error, HttpMessage, HttpRequest};
use futures::StreamExt;
use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};
use std::sync::Mutex;
use std::fs;
use std::io::Write;
use mime;
use rand::RngCore;
use rand_mt::Mt;
use lazy_static::lazy_static;
use image::ImageFormat;
use std::io::Read;

lazy_static! {
    static ref RNG: Mutex<Mt> = {
        let mut safe_rng = rand::rngs::OsRng;
        Mutex::new(Mt::new(safe_rng.next_u32()))
    };
    static ref USERS: Mutex<HashMap<String, User>> = Mutex::new(HashMap::new());
    static ref COOKIES: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref USED_INVITATION_CODES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref ADMIN_PASSWORD: String = {
        let mut password = String::new();
        for _ in 0..12 {
            let next_char = (0x30u8 + (RNG.lock().unwrap().next_u32() % 0x4D) as u8) as char;
            password.push(next_char);
        }
        println!("Admin password: {}", password);
        password
    };

}

#[derive(Serialize, Deserialize, Clone)]
struct User {
    username: String,
    password: String, // In a real application, store hashed passwords!
    email: String,
    is_admin: bool,
}

#[derive(Deserialize)]
struct RegisterData {
    username: String,
    password: String,
    email: String,
    invitation_code: String,
}

#[derive(Deserialize)]
struct LoginData {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct Image {
    url: String,
    alt: String,
}

fn init_admin() {
    let admin_user = User {
        username: "admin".to_string(),
        password: ADMIN_PASSWORD.clone(),
        email: "admin@example.com".to_string(),
        is_admin: true,
    };

    let mut users = USERS.lock().unwrap();
    users.insert("admin".to_string(), admin_user);
}

fn is_valid_invitation_code(code: &str) -> bool {
    {
        // First lock to check if the code has been used
        let used_codes = USED_INVITATION_CODES.lock().unwrap();
        if used_codes.contains(code) {
            return false;
        }
    }

    let code_bytes = code.as_bytes();

    if !code_bytes.iter().all(|&b| b.is_ascii_digit()) {
        return false;
    }

    let numbers: Vec<u32> = code_bytes.iter().map(|&b| (b - b'0') as u32).collect();

    let mut result = 0u32;
    for (i, &number) in numbers.iter().enumerate() {
        result = result.wrapping_add(number.wrapping_mul((i as u32).wrapping_add(23u32)));
    }

    let valid = result < 10;

    if valid {
        let mut used_codes = USED_INVITATION_CODES.lock().unwrap();
        used_codes.insert(code.to_string());
    }

    valid
}

fn check_and_delete_non_image(file_path: &std::path::Path) -> bool {
    let mut file = match fs::File::open(&file_path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_ok() {
        if let Ok(format) = image::guess_format(&buffer) {
            if format == ImageFormat::Jpeg || format == ImageFormat::Png {
                return true;
            }
        }
    }

    // If the file is not a valid image, delete it
    let _ = fs::remove_file(&file_path);
    false
}

async fn get_images(req: HttpRequest) -> impl Responder {
    let cookies = COOKIES.lock().unwrap();
    let cookie_opt = req.cookie("auth");

    if cookie_opt.is_none() {
        return HttpResponse::Unauthorized().body("Unauthorized: No auth cookie provided");
    }

    let cookie = cookie_opt.unwrap().value().to_string();
    if !cookies.contains_key(&cookie) || (cookies[&cookie] != "user" && cookies[&cookie] != "admin") {
        return HttpResponse::Unauthorized().body("Unauthorized");
    }

    let mut images = Vec::new();
    let image_dir = "./images/";

    match fs::read_dir(image_dir) {
        Ok(paths) => {
            for path in paths {
                if let Ok(entry) = path {
                    let file_path = entry.path();
                    if let Some(filename) = file_path.file_name() {
                        let filename_str = filename.to_string_lossy();

                        if check_and_delete_non_image(&file_path) {
                            images.push(Image {
                                url: format!("/api/image/{}", filename_str),
                                alt: filename_str.to_string(),
                            });
                        }
                    }
                }
            }
            HttpResponse::Ok().json(images)
        }
        Err(_) => HttpResponse::InternalServerError().body("Could not read image directory"),
    }
}

async fn serve_image(path: web::Path<String>) -> actix_web::Result<NamedFile> {
    let image_path = format!("./images/{}", path.into_inner());
    let image_path = std::path::Path::new(&image_path);

    if check_and_delete_non_image(image_path) {
        Ok(NamedFile::open(image_path)?)
    } else {
        Ok(NamedFile::open("unauthorized.html")?)  // Adjust this to the appropriate response you want for non-image files
    }
}

async fn upload_image(mut payload: Multipart, req: HttpRequest) -> Result<HttpResponse, Error> {
    let cookies = COOKIES.lock().unwrap();
    let cookie_opt = req.cookie("auth");

    if cookie_opt.is_none() {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized: No auth cookie provided"));
    }

    let cookie = cookie_opt.unwrap().value().to_string();
    if !cookies.contains_key(&cookie) || cookies[&cookie] != "admin" {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    while let Some(item) = payload.next().await {
        let mut field = item?;

        // Check if the content type is an image
        let content_type = field.content_type().clone();
        if !content_type.expect("REASON").type_().eq(&mime::IMAGE) {
            return Ok(HttpResponse::BadRequest().body("Only image files are allowed"));
        }

        let content_disposition = field.content_disposition();
        let mut filename = content_disposition.get_filename().map(|name| name.to_string()).unwrap_or_else(|| "".to_string());
        let mut filepath = "".to_string();

        let mut buffer = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            buffer.extend_from_slice(&data);
        }

        if !filename.is_empty() {
            filepath = format!("./images/{}", sanitize_filename::sanitize(&filename));
            match filename.rsplit('.').next() {
                Some(ext) if ext == "jpg" || ext == "png" || ext == &filename => (),
                _ => return Ok(HttpResponse::BadRequest().body("Only .jpg and .png files are allowed")),
            }
        } else {
            if let Some(first_line) = buffer.split(|&b| b == b'\n').next() {
                filepath = format!("./images/{}", String::from_utf8_lossy(first_line).trim().to_string());
            }else{
                return Ok(HttpResponse::BadRequest().body("Could not determine filename"));
            }
        }
        let mut f = web::block(move || fs::File::create(&filepath)).await??;
        f.write_all(&buffer)?;

    }
    Ok(HttpResponse::Ok().body("File uploaded successfully"))
}


async fn register_user(data: web::Json<RegisterData>) -> impl Responder {
    if !is_valid_invitation_code(&data.invitation_code) {
        return HttpResponse::BadRequest().body("Invalid invitation code");
    }

    let user = User {
        username: data.username.clone(),
        password: data.password.clone(), // In a real application, hash the password!
        email: data.email.clone(),
        is_admin: false,
    };

    let mut users = USERS.lock().unwrap();
    if users.contains_key(&data.username) {
        return HttpResponse::BadRequest().body("Username already exists");
    }

    users.insert(data.username.clone(), user);
    HttpResponse::Ok().body("User registered successfully")
}

async fn login_user(data: web::Json<LoginData>) -> impl Responder {
    let users = USERS.lock().unwrap();
    if let Some(user) = users.get(&data.username) {
        if user.password == data.password {
            let mut cookies = COOKIES.lock().unwrap();
            let cookie = RNG.lock().unwrap().next_u32().to_string();

            cookies.insert(cookie.clone(), if user.is_admin { "admin".to_string() } else { "user".to_string() });

            let response = if user.is_admin {
                HttpResponse::Found()
                    .cookie(
                        actix_web::cookie::Cookie::build("auth", cookie)
                            .path("/")
                            .secure(false)
                            .http_only(true)
                            .finish(),
                    )
                    .append_header(("Location", "/admin.html"))
                    .finish()
            } else {
                HttpResponse::Found()
                    .cookie(
                        actix_web::cookie::Cookie::build("auth", cookie)
                            .path("/")
                            .secure(false)
                            .http_only(true)
                            .finish(),
                    )
                    .append_header(("Location", "/user.html"))
                    .finish()
            };

            return response;
        }
    }
    HttpResponse::Unauthorized().body("Invalid username or password")
}

async fn admin_html(req: HttpRequest) -> Result<NamedFile, Error> {
    let cookies = COOKIES.lock().unwrap();

    // Check if the cookie is present
    if let Some(cookie) = req.cookie("auth") {
        let cookie_value = cookie.value().to_string();
        if cookies.contains_key(&cookie_value) && cookies[&cookie_value] == "admin" {
            Ok(NamedFile::open("admin.html")?)
        } else {
            Ok(NamedFile::open("unauthorized.html")?)
        }
    } else {
        // If the cookie is not present, return unauthorized
        Ok(NamedFile::open("unauthorized.html")?)
    }
}

async fn user_html(req: HttpRequest) -> Result<NamedFile, Error> {
    let cookies = COOKIES.lock().unwrap();
    if let Some(cookie) = req.cookie("auth") {
        let cookie_value = cookie.value().to_string();

        if cookies.contains_key(&cookie_value) && (cookies[&cookie_value] == "user" || cookies[&cookie_value] == "admin") {
            return Ok(NamedFile::open("user.html")?);
        }
    }
    Ok(NamedFile::open("unauthorized.html")?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_admin();

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .route("/api/user", web::get().to(get_images))
            .route("/api/image/{filename}", web::get().to(serve_image))
            .route("/admin/upload", web::post().to(upload_image))
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(login_user))
            .route("/admin.html", web::get().to(admin_html))
            .route("/user.html", web::get().to(user_html))
            .service(Files::new("/", "./dist").index_file("index.html"))
    })
        .bind("0.0.0.0:8881")?
        .run()
        .await
}
