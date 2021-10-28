/*
Package mimesniffer implements a MIME type sniffer for Go.
*/
package mimesniffer

import (
	"bytes"
	"encoding/binary"
	"mime"
	"net/http"
	"strings"
)

var (
	defaultSniffers = map[string]func([]byte) bool{
		"application/epub+zip":              applicationEPUBZip,
		"application/font-sfnt":             applicationFontSFNT,
		"application/font-woff":             applicationFontWOFF,
		"application/msword":                applicationMSWord,
		"application/rtf":                   applicationRTF,
		"application/vnd.ms-cab-compressed": applicationVNDMSCABCompressed,
		"application/vnd.ms-excel":          applicationVNDMSExcel,
		"application/vnd.ms-powerpoint":     applicationVNDMSPowerpoint,
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": applicationVNDOpenXMLFormatsOfficeDocumentPresentationMLPresentation,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         applicationVNDOpenXMLFormatsOfficeDocumentSpreadsheeetMLSheet,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   applicationVNDOpenXMLFormatsOfficeDocumentWordprocessingMLDocument,
		"application/x-7z-compressed":                                               applicationX7ZCompressed,
		"application/x-bzip2":                                                       applicationXBzip2,
		"application/x-compress":                                                    applicationXCompress,
		"application/x-deb":                                                         applicationXDEB,
		"application/x-executable":                                                  applicationXExecutable,
		"application/x-google-chrome-extension":                                     applicationXGoogleChromeExtension,
		"application/x-lzip":                                                        applicationXLzip,
		"application/x-msdownload":                                                  applicationXMSDownload,
		"application/x-nintendo-nes-rom":                                            applicationXNintendoNESROM,
		"application/x-rpm":                                                         applicationXRPM,
		"application/x-shockwave-flash":                                             applicationXShockwaveFlash,
		"application/x-sqlite3":                                                     applicationXSQLite3,
		"application/x-tar":                                                         applicationXTar,
		"application/x-unix-archive":                                                applicationXUNIXArchive,
		"application/x-xz":                                                          applicationXXZ,
		"audio/aac":                                                                 audioAAC,
		"audio/amr":                                                                 audioAMR,
		"audio/m4a":                                                                 audioM4A,
		"audio/ogg":                                                                 audioOgg,
		"audio/x-flac":                                                              audioXFLAC,
		"audio/x-wav":                                                               audioXWAV,
		"image/jp2":                                                                 imageJP2,
		"image/tiff":                                                                imageTIFF,
		"image/vnd.adobe.photoshop":                                                 imageVNDAdobePhotoshop,
		"image/x-canon-cr2":                                                         imageXCanonCR2,
		"video/mpeg":                                                                videoMPEG,
		"video/quicktime":                                                           videoQuickTime,
		"video/x-flv":                                                               videoXFLV,
		"video/x-m4v":                                                               videoXM4V,
		"video/x-matroska":                                                          videoXMatroska,
		"video/x-ms-wmv":                                                            videoXMSWMV,
		"video/x-msvideo":                                                           videoXMSVideo,
	}

	registeredSniffers = map[string]func([]byte) bool{}
)

// Register registers the sniffer for the `mimeType`. Invalid MIME types will be
// silently dropped.
func Register(mimeType string, sniffer func([]byte) bool) {
	mimeType = strings.ToLower(mimeType)
	if _, _, err := mime.ParseMediaType(mimeType); err != nil {
		return
	}

	registeredSniffers[mimeType] = sniffer
}

// Sniff sniffs the MIME type of the `b`. It considers at most the first 512
// bytes of the `b`.
//
// The `Sniff` always returns a valid MIME type. If it cannot determine a more
// specific one, it returns "application/octet-stream".
func Sniff(b []byte) string {
	if len(b) == 0 {
		return "application/octet-stream"
	}

	for mt, s := range registeredSniffers {
		if s(b) {
			return mt
		}
	}

	for mt, s := range defaultSniffers {
		if s(b) {
			return mt
		}
	}

	return http.DetectContentType(b)
}

// applicationEPUBZip reports whether the `b`'s MIME type is
// "application/epub+zip".
func applicationEPUBZip(b []byte) bool {
	return len(b) > 57 &&
		b[0] == 0x50 &&
		b[1] == 0x4b &&
		b[2] == 0x3 &&
		b[3] == 0x4 &&
		b[30] == 0x6d &&
		b[31] == 0x69 &&
		b[32] == 0x6d &&
		b[33] == 0x65 &&
		b[34] == 0x74 &&
		b[35] == 0x79 &&
		b[36] == 0x70 &&
		b[37] == 0x65 &&
		b[38] == 0x61 &&
		b[39] == 0x70 &&
		b[40] == 0x70 &&
		b[41] == 0x6c &&
		b[42] == 0x69 &&
		b[43] == 0x63 &&
		b[44] == 0x61 &&
		b[45] == 0x74 &&
		b[46] == 0x69 &&
		b[47] == 0x6f &&
		b[48] == 0x6e &&
		b[49] == 0x2f &&
		b[50] == 0x65 &&
		b[51] == 0x70 &&
		b[52] == 0x75 &&
		b[53] == 0x62 &&
		b[54] == 0x2b &&
		b[55] == 0x7a &&
		b[56] == 0x69 &&
		b[57] == 0x70
}

// applicationFontSFNT reports whether the `b`'s MIME type is
// "application/font-sfnt".
func applicationFontSFNT(b []byte) bool {
	return len(b) > 4 &&
		b[0] == 0x00 &&
		b[1] == 0x01 &&
		b[2] == 0x00 &&
		b[3] == 0x00 &&
		b[4] == 0x00 ||
		b[0] == 0x4f &&
			b[1] == 0x54 &&
			b[2] == 0x54 &&
			b[3] == 0x4f &&
			b[4] == 0x00
}

// applicationFontWOFF reports whether the `b`'s MIME type is
// "application/font-woff".
func applicationFontWOFF(b []byte) bool {
	return len(b) > 7 &&
		b[0] == 0x77 &&
		b[1] == 0x4f &&
		b[2] == 0x46 &&
		b[3] == 0x46 &&
		b[4] == 0x00 &&
		b[5] == 0x01 &&
		b[6] == 0x00 &&
		b[7] == 0x00 ||
		b[0] == 0x77 &&
			b[1] == 0x4f &&
			b[2] == 0x46 &&
			b[3] == 0x32 &&
			b[4] == 0x00 &&
			b[5] == 0x01 &&
			b[6] == 0x00 &&
			b[7] == 0x00
}

// applicationMSWord reports whether the `b`'s MIME type is
// "application/msword".
func applicationMSWord(b []byte) bool {
	return len(b) > 7 &&
		b[0] == 0xd0 &&
		b[1] == 0xcf &&
		b[2] == 0x11 &&
		b[3] == 0xe0 &&
		b[4] == 0xa1 &&
		b[5] == 0xb1 &&
		b[6] == 0x1a &&
		b[7] == 0xe1
}

// applicationRTF reports whether the `b`'s MIME type is "application/rtf".
func applicationRTF(b []byte) bool {
	return len(b) > 4 &&
		b[0] == 0x7b &&
		b[1] == 0x5c &&
		b[2] == 0x72 &&
		b[3] == 0x74 &&
		b[4] == 0x66
}

// applicationVNDMSCABCompressed reports whether the `b`'s MIME type is
// "application/vnd.ms-cab-compressed".
func applicationVNDMSCABCompressed(b []byte) bool {
	return len(b) > 3 &&
		(b[0] == 0x4d &&
			b[1] == 0x53 &&
			b[2] == 0x43 &&
			b[3] == 0x46 ||
			b[0] == 0x49 &&
				b[1] == 0x53 &&
				b[2] == 0x63 &&
				b[3] == 0x28)
}

// applicationVNDMSExcel reports whether the `b`'s MIME type is
// "application/vnd.ms-excel".
func applicationVNDMSExcel(b []byte) bool {
	return len(b) > 7 &&
		b[0] == 0xd0 &&
		b[1] == 0xcf &&
		b[2] == 0x11 &&
		b[3] == 0xe0 &&
		b[4] == 0xa1 &&
		b[5] == 0xb1 &&
		b[6] == 0x1a &&
		b[7] == 0xe1
}

// applicationVNDMSPowerpoint reports whether the `b`'s MIME type is
// "application/vnd.ms-powerpoint".
func applicationVNDMSPowerpoint(b []byte) bool {
	return len(b) > 7 &&
		b[0] == 0xd0 &&
		b[1] == 0xcf &&
		b[2] == 0x11 &&
		b[3] == 0xe0 &&
		b[4] == 0xa1 &&
		b[5] == 0xb1 &&
		b[6] == 0x1a &&
		b[7] == 0xe1
}

// applicationVNDOpenXMLFormatsOfficeDocumentPresentationMLPresentation reports
// whether the `b`'s MIME type is
// "application/vnd.openxmlformats-officedocument.presentationml.presentation".
func applicationVNDOpenXMLFormatsOfficeDocumentPresentationMLPresentation(
	b []byte,
) bool {
	sign := []byte{'P', 'K', 0x03, 0x04}
	pptx := []byte("ppt/")
	ctxml := []byte("[Content_Types].xml")
	rels := []byte("_rels/.rels")
	bl, sl, l, cl, rl := len(b), len(sign), len(pptx), len(ctxml), len(rels)

	if bl < sl || !bytes.Equal(b[:sl], sign) {
		return false
	}

	if bl < l+0x1e && bytes.Equal(b[0x1e:l+0x1e], pptx) {
		return true
	}

	if (bl < cl+0x1e || !bytes.Equal(b[0x1e:cl+0x1d], ctxml)) &&
		(bl < rl+0x1e || !bytes.Equal(b[0x1e:rl+0x1d], rels)) {
		return false
	}

	start := int(binary.BigEndian.Uint32(b[18:22]) + 49)
	end := start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i := bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	if bl < l+start && bytes.Equal(b[start:l+start], pptx) {
		return true
	}

	start += 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26

	return bl < l+start && bytes.Equal(b[start:l+start], pptx)
}

// applicationVNDOpenXMLFormatsOfficeDocumentSpreadsheeetMLSheet reports whether
// the `b`'s MIME type is
// "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".
func applicationVNDOpenXMLFormatsOfficeDocumentSpreadsheeetMLSheet(
	b []byte,
) bool {
	sign := []byte{'P', 'K', 0x03, 0x04}
	xlsx := []byte("xl/")
	ctxml := []byte("[Content_Types].xml")
	rels := []byte("_rels/.rels")
	bl, sl, l, cl, rl := len(b), len(sign), len(xlsx), len(ctxml), len(rels)

	if bl < sl || !bytes.Equal(b[:sl], sign) {
		return false
	}

	if bl < l+0x1e && bytes.Equal(b[0x1e:l+0x1e], xlsx) {
		return true
	}

	if (bl < cl+0x1e || !bytes.Equal(b[0x1e:cl+0x1d], ctxml)) &&
		(bl < rl+0x1e || !bytes.Equal(b[0x1e:rl+0x1d], rels)) {
		return false
	}

	start := int(binary.BigEndian.Uint32(b[18:22]) + 49)
	end := start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i := bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	if bl < l+start && bytes.Equal(b[start:l+start], xlsx) {
		return true
	}

	start += 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26

	return bl < l+start && bytes.Equal(b[start:l+start], xlsx)
}

// applicationVNDOpenXMLFormatsOfficeDocumentWordprocessingMLDocument reports
// whether the `b`'s MIME type is
// "application/vnd.openxmlformats-officedocument.wordprocessingml.document".
func applicationVNDOpenXMLFormatsOfficeDocumentWordprocessingMLDocument(
	b []byte,
) bool {
	sign := []byte{'P', 'K', 0x03, 0x04}
	word := []byte("word/")
	ctxml := []byte("[Content_Types].xml")
	rels := []byte("_rels/.rels")
	bl, sl, l, cl, rl := len(b), len(sign), len(word), len(ctxml), len(rels)

	if bl < sl || !bytes.Equal(b[:sl], sign) {
		return false
	}

	if bl < l+0x1e && bytes.Equal(b[0x1e:l+0x1e], word) {
		return true
	}

	if (bl < cl+0x1e || !bytes.Equal(b[0x1e:cl+0x1d], ctxml)) &&
		(bl < rl+0x1e || !bytes.Equal(b[0x1e:rl+0x1d], rels)) {
		return false
	}

	start := int(binary.BigEndian.Uint32(b[18:22]) + 49)
	end := start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i := bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26
	if bl < l+start && bytes.Equal(b[start:l+start], word) {
		return true
	}

	start += 26
	end = start + 6000
	if end > bl {
		end = bl
	}

	if start >= end {
		return false
	}

	i = bytes.Index(b[start:end], sign)
	if i == -1 {
		return false
	}

	start += i + 4 + 26

	return bl < l+start && bytes.Equal(b[start:l+start], word)
}

// applicationX7ZCompressed reports whether the `b`'s MIME type is
// "application/x-7z-compressed".
func applicationX7ZCompressed(b []byte) bool {
	return len(b) > 5 &&
		b[0] == 0x37 &&
		b[1] == 0x7a &&
		b[2] == 0xbc &&
		b[3] == 0xaf &&
		b[4] == 0x27 &&
		b[5] == 0x1c
}

// applicationXBzip2 reports whether the `b`'s MIME type is
// "application/x-bzip2".
func applicationXBzip2(b []byte) bool {
	return len(b) > 2 &&
		b[0] == 0x42 &&
		b[1] == 0x5a &&
		b[2] == 0x68
}

// applicationXCompress reports whether the `b`'s MIME type is
// "application/x-compress".
func applicationXCompress(b []byte) bool {
	return len(b) > 1 &&
		(b[0] == 0x1f &&
			b[1] == 0xa0 ||
			b[0] == 0x1f &&
				b[1] == 0x9d)
}

// applicationXDEB reports whether the `b`'s MIME type is "application/x-deb".
func applicationXDEB(b []byte) bool {
	return len(b) > 20 &&
		b[0] == 0x21 &&
		b[1] == 0x3c &&
		b[2] == 0x61 &&
		b[3] == 0x72 &&
		b[4] == 0x63 &&
		b[5] == 0x68 &&
		b[6] == 0x3e &&
		b[7] == 0x0a &&
		b[8] == 0x64 &&
		b[9] == 0x65 &&
		b[10] == 0x62 &&
		b[11] == 0x69 &&
		b[12] == 0x61 &&
		b[13] == 0x6e &&
		b[14] == 0x2d &&
		b[15] == 0x62 &&
		b[16] == 0x69 &&
		b[17] == 0x6e &&
		b[18] == 0x61 &&
		b[19] == 0x72 &&
		b[20] == 0x79
}

// applicationXExecutable reports whether the `b`'s MIME type is
// "application/x-executable".
func applicationXExecutable(b []byte) bool {
	return len(b) > 52 &&
		b[0] == 0x7f &&
		b[1] == 0x45 &&
		b[2] == 0x4c &&
		b[3] == 0x46
}

// applicationXGoogleChromeExtension reports whether the `b`'s MIME type is
// "application/x-google-chrome-extension".
func applicationXGoogleChromeExtension(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x43 &&
		b[1] == 0x72 &&
		b[2] == 0x32 &&
		b[3] == 0x34
}

// applicationXLzip reports whether the `b`'s MIME type is "application/x-lzip".
func applicationXLzip(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x4c &&
		b[1] == 0x5a &&
		b[2] == 0x49 &&
		b[3] == 0x50
}

// applicationXMSDownload reports whether the `b`'s MIME type is
// "application/x-msdownload".
func applicationXMSDownload(b []byte) bool {
	return len(b) > 1 &&
		b[0] == 0x4d &&
		b[1] == 0x5a
}

// applicationXNintendoNESROM reports whether the `b`'s MIME type is
// "application/x-nintendo-nes-rom".
func applicationXNintendoNESROM(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x4e &&
		b[1] == 0x45 &&
		b[2] == 0x53 &&
		b[3] == 0x1a
}

// applicationXRPM reports whether the `b`'s MIME type is "application/x-rpm".
func applicationXRPM(b []byte) bool {
	return len(b) > 96 &&
		b[0] == 0xed &&
		b[1] == 0xab &&
		b[2] == 0xee &&
		b[3] == 0xdb
}

// applicationXShockwaveFlash reports whether the `b`'s MIME type is
// "application/x-shockwave-flash".
func applicationXShockwaveFlash(b []byte) bool {
	return len(b) > 2 &&
		(b[0] == 0x43 ||
			b[0] == 0x46) &&
		b[1] == 0x57 &&
		b[2] == 0x53
}

// applicationXSQLite3 reports whether the `b`'s MIME type is
// "application/x-sqlite3".
func applicationXSQLite3(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x53 &&
		b[1] == 0x51 &&
		b[2] == 0x4c &&
		b[3] == 0x69
}

// applicationXTar reports whether the `b`'s MIME type is "application/x-tar".
func applicationXTar(b []byte) bool {
	return len(b) > 261 &&
		b[257] == 0x75 &&
		b[258] == 0x73 &&
		b[259] == 0x74 &&
		b[260] == 0x61 &&
		b[261] == 0x72
}

// applicationXUNIXArchive reports whether the `b`'s MIME type is
// "application/x-unix-archive".
func applicationXUNIXArchive(b []byte) bool {
	return len(b) > 6 &&
		b[0] == 0x21 &&
		b[1] == 0x3c &&
		b[2] == 0x61 &&
		b[3] == 0x72 &&
		b[4] == 0x63 &&
		b[5] == 0x68 &&
		b[6] == 0x3e
}

// applicationXXZ reports whether the `b`'s MIME type is "application/x-xz".
func applicationXXZ(b []byte) bool {
	return len(b) > 5 &&
		b[0] == 0xfd &&
		b[1] == 0x37 &&
		b[2] == 0x7a &&
		b[3] == 0x58 &&
		b[4] == 0x5a &&
		b[5] == 0x00
}

// audioAAC reports whether the `b`'s MIME type is "audio/aac".
func audioAAC(b []byte) bool {
	return len(b) > 1 &&
		(b[0] == 0xff &&
			b[1] == 0xf1 ||
			b[0] == 0xff &&
				b[1] == 0xf9)
}

// audioAMR reports whether the `b`'s MIME type is "audio/amr".
func audioAMR(b []byte) bool {
	return len(b) > 11 &&
		b[0] == 0x23 &&
		b[1] == 0x21 &&
		b[2] == 0x41 &&
		b[3] == 0x4d &&
		b[4] == 0x52 &&
		b[5] == 0x0a
}

// audioM4A reports whether the `b`'s MIME type is "audio/m4a".
func audioM4A(b []byte) bool {
	return len(b) > 10 &&
		(b[4] == 0x66 &&
			b[5] == 0x74 &&
			b[6] == 0x79 &&
			b[7] == 0x70 &&
			b[8] == 0x4d &&
			b[9] == 0x34 &&
			b[10] == 0x41 ||
			b[0] == 0x4d &&
				b[1] == 0x34 &&
				b[2] == 0x41 &&
				b[3] == 0x20)
}

// audioOgg reports whether the `b`'s MIME type is "audio/ogg".
func audioOgg(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x4f &&
		b[1] == 0x67 &&
		b[2] == 0x67 &&
		b[3] == 0x53
}

// audioXFLAC reports whether the `b`'s MIME type is "audio/x-flac".
func audioXFLAC(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x66 &&
		b[1] == 0x4c &&
		b[2] == 0x61 &&
		b[3] == 0x43
}

// audioXWAV reports whether the `b`'s MIME type is "audio/x-wav".
func audioXWAV(b []byte) bool {
	return len(b) > 11 &&
		b[0] == 0x52 &&
		b[1] == 0x49 &&
		b[2] == 0x46 &&
		b[3] == 0x46 &&
		b[8] == 0x57 &&
		b[9] == 0x41 &&
		b[10] == 0x56 &&
		b[11] == 0x45
}

// imageJP2 reports whether the `b`'s MIME type is "image/jp2".
func imageJP2(b []byte) bool {
	return len(b) > 12 &&
		b[0] == 0x0 &&
		b[1] == 0x0 &&
		b[2] == 0x0 &&
		b[3] == 0xc &&
		b[4] == 0x6a &&
		b[5] == 0x50 &&
		b[6] == 0x20 &&
		b[7] == 0x20 &&
		b[8] == 0xd &&
		b[9] == 0xa &&
		b[10] == 0x87 &&
		b[11] == 0xa &&
		b[12] == 0x0
}

// imageTIFF reports whether the `b`'s MIME type is "image/tiff".
func imageTIFF(b []byte) bool {
	return len(b) > 3 &&
		(b[0] == 0x49 &&
			b[1] == 0x49 &&
			b[2] == 0x2a &&
			b[3] == 0x0 ||
			b[0] == 0x4d &&
				b[1] == 0x4d &&
				b[2] == 0x0 &&
				b[3] == 0x2a)
}

// imageVNDAdobePhotoshop reports whether the `b`'s MIME type is
// "image/vnd.adobe.photoshop".
func imageVNDAdobePhotoshop(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x38 &&
		b[1] == 0x42 &&
		b[2] == 0x50 &&
		b[3] == 0x53
}

// imageXCanonCR2 reports whether the `b`'s MIME type is "image/x-canon-cr2".
func imageXCanonCR2(b []byte) bool {
	return len(b) > 9 &&
		(b[0] == 0x49 &&
			b[1] == 0x49 &&
			b[2] == 0x2a &&
			b[3] == 0x0 ||
			b[0] == 0x4d &&
				b[1] == 0x4d &&
				b[2] == 0x0 &&
				b[3] == 0x2a) &&
		b[8] == 0x43 && b[9] == 0x52
}

// videoMPEG reports whether the `b`'s MIME type is "video/mpeg".
func videoMPEG(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x0 &&
		b[1] == 0x0 &&
		b[2] == 0x1 &&
		b[3] >= 0xb0 &&
		b[3] <= 0xbf
}

// videoQuickTime reports whether the `b`'s MIME type is "video/quicktime".
func videoQuickTime(b []byte) bool {
	return len(b) > 15 &&
		(b[0] == 0x0 &&
			b[1] == 0x0 &&
			b[2] == 0x0 &&
			b[3] == 0x14 &&
			b[4] == 0x66 &&
			b[5] == 0x74 &&
			b[6] == 0x79 &&
			b[7] == 0x70 ||
			b[4] == 0x6d &&
				b[5] == 0x6f &&
				b[6] == 0x6f &&
				b[7] == 0x76 ||
			b[4] == 0x6d &&
				b[5] == 0x64 &&
				b[6] == 0x61 &&
				b[7] == 0x74 ||
			b[12] == 0x6d &&
				b[13] == 0x64 &&
				b[14] == 0x61 &&
				b[15] == 0x74)
}

// videoXFLV reports whether the `b`'s MIME type is "video/x-flv".
func videoXFLV(b []byte) bool {
	return len(b) > 3 &&
		b[0] == 0x46 &&
		b[1] == 0x4c &&
		b[2] == 0x56 &&
		b[3] == 0x01
}

// videoXM4V reports whether the `b`'s MIME type is "video/x-m4v".
func videoXM4V(b []byte) bool {
	return len(b) > 10 &&
		b[4] == 0x66 &&
		b[5] == 0x74 &&
		b[6] == 0x79 &&
		b[7] == 0x70 &&
		b[8] == 0x4d &&
		b[9] == 0x34 &&
		b[10] == 0x56
}

// videoXMatroska reports whether the `b`'s MIME type is "video/x-matroska".
func videoXMatroska(b []byte) bool {
	return (len(b) > 15 &&
		b[0] == 0x1a &&
		b[1] == 0x45 &&
		b[2] == 0xdf &&
		b[3] == 0xa3 &&
		b[4] == 0x93 &&
		b[5] == 0x42 &&
		b[6] == 0x82 &&
		b[7] == 0x88 &&
		b[8] == 0x6d &&
		b[9] == 0x61 &&
		b[10] == 0x74 &&
		b[11] == 0x72 &&
		b[12] == 0x6f &&
		b[13] == 0x73 &&
		b[14] == 0x6b &&
		b[15] == 0x61) ||
		(len(b) > 38 &&
			b[31] == 0x6d &&
			b[32] == 0x61 &&
			b[33] == 0x74 &&
			b[34] == 0x72 &&
			b[35] == 0x6f &&
			b[36] == 0x73 &&
			b[37] == 0x6b &&
			b[38] == 0x61)
}

// videoXMSWMV reports whether the `b`'s MIME type is "video/x-ms-wmv".
func videoXMSWMV(b []byte) bool {
	return len(b) > 9 &&
		b[0] == 0x30 &&
		b[1] == 0x26 &&
		b[2] == 0xb2 &&
		b[3] == 0x75 &&
		b[4] == 0x8e &&
		b[5] == 0x66 &&
		b[6] == 0xcf &&
		b[7] == 0x11 &&
		b[8] == 0xa6 &&
		b[9] == 0xd9
}

// videoXMSVideo reports whether the `b`'s MIME type is "video/x-msvideo".
func videoXMSVideo(b []byte) bool {
	return len(b) > 10 &&
		b[0] == 0x52 &&
		b[1] == 0x49 &&
		b[2] == 0x46 &&
		b[3] == 0x46 &&
		b[8] == 0x41 &&
		b[9] == 0x56 &&
		b[10] == 0x49
}
