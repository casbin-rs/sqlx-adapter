#!/bin/bash

if [[ ! $# > 0 ]]; then
    echo "help: ./login-db.sh --mysql|--postgres" && exit 1;
elif [ "$1" == "--postgres" ]; then
    psql postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin;
elif [ "$1" == "--mysql" ]; then
    mysql -h 127.0.0.1 -u casbin_rs -pcasbin_rs casbin;
else
    echo "invalid argument: $1" && exit 1;
fi
