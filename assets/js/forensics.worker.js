'use strict';

const MAGIC_SIGS = [
  { name: 'Imagem JPEG', exts: ['jpg', 'jpeg', 'jfif'], test: (h) => h.startsWith('FFD8FF') },
  { name: 'Imagem PNG', exts: ['png'], test: (h) => h.startsWith('89504E470D0A1A0A') },
  { name: 'Imagem GIF', exts: ['gif'], test: (h) => h.startsWith('47494638') },
  { name: 'Documento PDF', exts: ['pdf'], test: (h) => h.startsWith('25504446') },
  { name: 'ZIP / Office / APK', exts: ['zip', 'docx', 'xlsx', 'pptx', 'apk', 'jar', 'odt'], test: (h) => h.startsWith('504B0304') || h.startsWith('504B0506') },
  { name: 'Arquivo RAR', exts: ['rar'], test: (h) => h.startsWith('526172211A07') },
  { name: 'Arquivo 7-Zip', exts: ['7z'], test: (h) => h.startsWith('377ABCAF271C') },
  { name: 'Executável PE (EXE/DLL)', exts: ['exe', 'dll', 'scr', 'sys'], test: (h) => h.startsWith('4D5A') },
  { name: 'Executável ELF (Linux)', exts: ['elf', 'so', 'bin', ''], test: (h) => h.startsWith('7F454C46') },
  { name: 'Imagem WebP', exts: ['webp'], test: (h) => h.startsWith('52494646') && h.slice(16, 24) === '57454250' },
  { name: 'ISO Media (MP4/MOV/HEIC)', exts: ['mp4', 'm4a', 'mov', 'heic', 'heif', 'avif'], test: (h) => h.slice(8, 16) === '66747970' },
  { name: 'Imagem TIFF', exts: ['tif', 'tiff'], test: (h) => h.startsWith('49492A00') || h.startsWith('4D4D002A') },
