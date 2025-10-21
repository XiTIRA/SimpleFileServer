# Simple File Server

A very simple server that exposes a file system through a REST API.

## But Why?

It's a simple way of serving files across systems.

Say you have a Windows and Linux machine, and you want to share a folder between them. Typically
you would have to use a network share, but that's not always possible.

This server allows you to serve files from a local folder, and then access them from any machine
that has access to the server.

It is highly recommended that you do not use this server behind a proxy over HTTPS with the intent of serving
files to the public internet! 

While steps are being taken to make this server more secure, it's not intended to be a replacement for
dedicated file servers such as FTP, Samba, S3 etc. It's more to act as an intermediate bridge while other technologies are deployed and established.

## Api Documentation

The api is documented using OpenApi and Scalar, navigate to host:port/scalar to view it.