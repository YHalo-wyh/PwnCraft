FROM httpd:2.4.53

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
RUN apt-get update && \
    apt-get install -y curl ca-certificates apt-transport-https lsb-release gnupg net-tools procps
RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs
COPY ./blog /app
WORKDIR /app
RUN npm install

CMD ["/start.sh"]

EXPOSE 18888