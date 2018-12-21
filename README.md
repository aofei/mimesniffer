# MIMESniffer

[![Build Status](https://travis-ci.org/aofei/mimesniffer.svg?branch=master)](https://travis-ci.org/aofei/mimesniffer)
[![Coverage Status](https://coveralls.io/repos/github/aofei/mimesniffer/badge.svg?branch=master)](https://coveralls.io/github/aofei/mimesniffer?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/aofei/mimesniffer)](https://goreportcard.com/report/github.com/aofei/mimesniffer)
[![GoDoc](https://godoc.org/github.com/aofei/mimesniffer?status.svg)](https://godoc.org/github.com/aofei/mimesniffer)

A MIME type sniffer for Go.

MIMESniffer implements the algorithm described at
[here](https://mimesniff.spec.whatwg.org) to determine the MIME type of the
given data. So it can be used as a substitute for `http.DetectContentType()`.

## Features

* Extremely easy to use
	* Only two functions
		* `mimesniffer.Register()`
		* `mimesniffer.Sniff()`
* Quite fast
* Supports a wide range of MIME types
	* `application/epub+zip`
	* `application/font-sfnt`
	* `application/font-woff`
	* `application/msword`
	* `application/octet-stream`
	* `application/ogg`
	* `application/pdf`
	* `application/postscript`
	* `application/rtf`
	* `application/vnd.ms-cab-compressed`
	* `application/vnd.ms-excel`
	* `application/vnd.ms-fontobject`
	* `application/vnd.ms-powerpoint`
	* `application/vnd.openxmlformats-officedocument.presentationml.presentation`
	* `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`
	* `application/vnd.openxmlformats-officedocument.wordprocessingml.document`
	* `application/wasm`
	* `application/x-7z-compressed`
	* `application/x-bzip2`
	* `application/x-compress`
	* `application/x-deb`
	* `application/x-executable`
	* `application/x-google-chrome-extension`
	* `application/x-gzip`
	* `application/x-lzip`
	* `application/x-msdownload`
	* `application/x-nintendo-nes-rom`
	* `application/x-rar-compressed`
	* `application/x-rpm`
	* `application/x-shockwave-flash`
	* `application/x-sqlite3`
	* `application/x-tar`
	* `application/x-unix-archive`
	* `application/x-xz`
	* `application/zip`
	* `audio/aac`
	* `audio/aiff`
	* `audio/amr`
	* `audio/basic`
	* `audio/m4a`
	* `audio/midi`
	* `audio/mpeg`
	* `audio/ogg`
	* `audio/wave`
	* `audio/x-flac`
	* `audio/x-wav`
	* `font/collection`
	* `font/otf`
	* `font/ttf`
	* `font/woff2`
	* `font/woff`
	* `image/bmp`
	* `image/gif`
	* `image/jp2`
	* `image/jpeg`
	* `image/png`
	* `image/tiff`
	* `image/vnd.adobe.photoshop`
	* `image/vnd.microsoft.icon`
	* `image/webp`
	* `image/x-canon-cr2`
	* `text/html; charset=utf-8`
	* `text/plain; charset=utf-16be`
	* `text/plain; charset=utf-16le`
	* `text/plain; charset=utf-8`
	* `text/xml; charset=utf-8`
	* `video/avi`
	* `video/mp4`
	* `video/mpeg`
	* `video/quicktime`
	* `video/webm`
	* `video/x-flv`
	* `video/x-m4v`
	* `video/x-matroska`
	* `video/x-ms-wmv`
	* `video/x-msvideo`

## Installation

Open your terminal and execute

```bash
$ go get github.com/aofei/mimesniffer
```

done.

> The only requirement is the [Go](https://golang.org), at least v1.2.

## Community

If you want to discuss this project, or ask questions about it, simply post
questions or ideas [here](https://github.com/aofei/mimesniffer/issues).

## Contributing

If you want to help build this project, simply follow
[this](https://github.com/aofei/mimesniffer/wiki/Contributing) to send pull requests
[here](https://github.com/aofei/mimesniffer/pulls).

## License

This project is licensed under the Unlicense.

License can be found [here](LICENSE).
