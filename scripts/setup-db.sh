#!/bin/bash

DIS=$(lsb_release -is)

command -v docker > /dev/null 2>&1 || {
    echo "Please install docker before running this script." && exit 1;
}

if [ $DIS == "Ubuntu" ]; then
    sudo apt install -y \
        libpq-dev \
        libmysqlclient-dev \
        postgresql-client \
        mysql-client-core;

elif [ $DIS == "Deepin" ]; then
    sudo apt install -y \
        libpq-dev \
        libmysql++-dev \
        mysql-client \
        postgresql-client;
elif [ $DIS == "ArchLinux" ] || [ $DIS == "ManjaroLinux" ]; then
    sudo pacman -S libmysqlclient \
        postgresql-libs \
        mysql-clients \;
else
    echo "Unsupported system: $DIS" && exit 1;
fi

docker run -itd \
    --restart always \
    -e POSTGRES_USER=casbin_rs \
    -e POSTGRES_PASSWORD=casbin_rs \
    -e POSTGRES_DB=casbin \
    -p 5432:5432 \
    -v /srv/docker/postgresql:/var/lib/postgresql \
    postgres:11;

docker run -itd \
    --restart always \
    -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
    -e MYSQL_USER=casbin_rs \
    -e MYSQL_PASSWORD=casbin_rs \
    -e MYSQL_DATABASE=casbin \
    -p 3306:3306 \
    -v /srv/docker/mysql:/var/lib/mysql \
    mysql:8 \
    --default-authentication-plugin=mysql_native_password;
