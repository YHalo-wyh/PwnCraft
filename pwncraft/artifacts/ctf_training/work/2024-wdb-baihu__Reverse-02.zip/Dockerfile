FROM ubuntu:22.04

RUN sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN apt-get clean

COPY httpd /home/httpd
COPY www /home/www
COPY flag /flag


RUN chmod +x /home/httpd
EXPOSE 8080
WORKDIR "/home/"
CMD [ "/home/httpd"]
