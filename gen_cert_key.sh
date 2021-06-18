#!/bin/sh
openssl req -x509 -nodes -days 1826 -newkey rsa:4096 -keyout toy_el_server.key -out toy_el_server.cert
