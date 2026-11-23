const IFD0_TAGS = {
  0x010e: 'Descricao',
  0x010f: 'Fabricante',
  0x0110: 'Modelo',
  0x0112: 'Orientacao',
  0x0131: 'Software',
  0x0132: 'DataModificacao',
  0x013b: 'Artista',
  0x8298: 'Copyright',
  0x8769: '_ExifIFDPointer',
  0x8825: '_GPSIFDPointer'
};

const EXIF_TAGS = {
  0x829a: 'TempoExposicao',
  0x829d: 'AberturaF',
  0x8827: 'ISO',
  0x9003: 'DataOriginal',
  0x9004: 'DataDigitalizacao',
  0x920a: 'DistanciaFocal',
  0xa002: 'LarguraExif',
  0xa003: 'AlturaExif',
  0xa430: 'ProprietarioCamera',
  0xa431: 'NumeroSerieCamera',
  0xa433: 'FabricanteLente',
  0xa434: 'ModeloLente'
};

const GPS_TAGS = {
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x001d: 'GPSDateStamp'
};

function readAscii(view, offset, length) {
  let out = '';
  const end = Math.min(view.byteLength, offset + length);
  for (let i = offset; i < end; i++) {
    const c = view.getUint8(i);
    if (c === 0) break;
    out += String.fromCharCode(c);
  }
  return out.trim();
}

function readTagValue(view, tiffStart, entryOffset, type, count, littleEndian) {
  const typeSizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
  const unitSize = typeSizes[type] || 1;
  const byteSize = unitSize * count;
  const valueOffset = byteSize <= 4
    ? entryOffset + 8
    : tiffStart + view.getUint32(entryOffset + 8, littleEndian);

  if (valueOffset < 0 || valueOffset + byteSize > view.byteLength) return null;

  if (type === 2) return readAscii(view, valueOffset, count);
  if (type === 3) {
    if (count === 1) return view.getUint16(valueOffset, littleEndian);
    const arr = [];
    for (let i = 0; i < count; i++) arr.push(view.getUint16(valueOffset + i * 2, littleEndian));
    return arr;
  }
  if (type === 4) {
    if (count === 1) return view.getUint32(valueOffset, littleEndian);
    const arr = [];
    for (let i = 0; i < count; i++) arr.push(view.getUint32(valueOffset + i * 4, littleEndian));
    return arr;
  }
  if (type === 5 || type === 10) {
    const readOne = (pos) => {
      const num = type === 5 ? view.getUint32(pos, littleEndian) : view.getInt32(pos, littleEndian);
      const den = type === 5 ? view.getUint32(pos + 4, littleEndian) : view.getInt32(pos + 4, littleEndian);
      return den ? num / den : 0;
    };
    if (count === 1) return readOne(valueOffset);
    const arr = [];
    for (let i = 0; i < count; i++) arr.push(readOne(valueOffset + i * 8));
    return arr;
  }
  return null;
}

function parseIfd(view, tiffStart, ifdOffset, littleEndian, tagDict) {
  const out = {};
  const base = tiffStart + ifdOffset;
  if (base < 0 || base + 2 > view.byteLength) return out;
  const count = view.getUint16(base, littleEndian);
  for (let i = 0; i < count; i++) {
    const entryOffset = base + 2 + i * 12;
    if (entryOffset + 12 > view.byteLength) break;
    const tagId = view.getUint16(entryOffset, littleEndian);
    const name = tagDict[tagId];
    if (!name) continue;
    const type = view.getUint16(entryOffset + 2, littleEndian);
    const numValues = view.getUint32(entryOffset + 4, littleEndian);
    const val = readTagValue(view, tiffStart, entryOffset, type, numValues, littleEndian);
    if (val !== null && val !== '') out[name] = val;
  }
  return out;
}

function dmsToDecimal(dms, ref) {
  if (!Array.isArray(dms) || dms.length < 3) return null;
  let dec = dms[0] + dms[1] / 60 + dms[2] / 3600;
  if (ref === 'S' || ref === 'W') dec = -dec;
  return Number(dec.toFixed(6));
}

function parseJpegExif(view) {
  const result = { format: 'JPEG', tags: {}, gps: null, dimensions: null };
  let offset = 2;

  while (offset + 4 < view.byteLength) {
    if (view.getUint8(offset) !== 0xff) break;
    const marker = view.getUint8(offset + 1);
    if (marker === 0xda || marker === 0xd9) break; // SOS / EOI
    const segLen = view.getUint16(offset + 2, false);
    if (segLen < 2 || offset + 2 + segLen > view.byteLength) break;

    // SOF0 / SOF2 dimensions
    if ((marker === 0xc0 || marker === 0xc2) && offset + 9 < view.byteLength) {
      result.dimensions = {
        height: view.getUint16(offset + 5, false),
        width: view.getUint16(offset + 7, false)
      };
    }

    // APP1 EXIF
    if (marker === 0xe1 && segLen > 10 && readAscii(view, offset + 4, 4) === 'Exif') {
      const tiffStart = offset + 10;
      const endian = readAscii(view, tiffStart, 2);
      const littleEndian = endian === 'II';
      const firstIfdOffset = view.getUint32(tiffStart + 4, littleEndian);
      const ifd0 = parseIfd(view, tiffStart, firstIfdOffset, littleEndian, IFD0_TAGS);

      const exifPtr = ifd0._ExifIFDPointer;
      const gpsPtr = ifd0._GPSIFDPointer;
      delete ifd0._ExifIFDPointer;
      delete ifd0._GPSIFDPointer;

      Object.assign(result.tags, ifd0);

      if (typeof exifPtr === 'number') {
        const exifData = parseIfd(view, tiffStart, exifPtr, littleEndian, EXIF_TAGS);
        if (typeof exifData.TempoExposicao === 'number' && exifData.TempoExposicao > 0 && exifData.TempoExposicao < 1) {
          exifData.TempoExposicao = `1/${Math.round(1 / exifData.TempoExposicao)} s`;
        }
        if (typeof exifData.AberturaF === 'number') exifData.AberturaF = `f/${exifData.AberturaF.toFixed(1)}`;
        if (typeof exifData.DistanciaFocal === 'number') exifData.DistanciaFocal = `${exifData.DistanciaFocal.toFixed(1)} mm`;
        Object.assign(result.tags, exifData);
      }

      if (typeof gpsPtr === 'number') {
        const gpsRaw = parseIfd(view, tiffStart, gpsPtr, littleEndian, GPS_TAGS);
        const lat = dmsToDecimal(gpsRaw.GPSLatitude, gpsRaw.GPSLatitudeRef);
        const lon = dmsToDecimal(gpsRaw.GPSLongitude, gpsRaw.GPSLongitudeRef);
        if (lat !== null && lon !== null) {
          result.gps = {
            latitude: lat,
            longitude: lon,
            altitude: typeof gpsRaw.GPSAltitude === 'number' ? `${gpsRaw.GPSAltitude.toFixed(1)} m` : null,
            date: gpsRaw.GPSDateStamp || null
          };
        }
      }
    }

    offset += 2 + segLen;
  }

  return result;
}

function parsePngMetadata(view) {
  const result = { format: 'PNG', tags: {}, gps: null, dimensions: null };
  let offset = 8;
  while (offset + 12 <= view.byteLength) {
    const length = view.getUint32(offset, false);
    const type = readAscii(view, offset + 4, 4);
    const dataStart = offset + 8;
    if (dataStart + length > view.byteLength) break;

    if (type === 'IHDR' && length >= 13) {
      result.dimensions = {
        width: view.getUint32(dataStart, false),
        height: view.getUint32(dataStart + 4, false)
      };
      result.tags.ProfundidadeBits = view.getUint8(dataStart + 8);
    } else if (type === 'tEXt' && length > 0 && length < 4096) {
      const raw = readAscii(view, dataStart, length);
      let sep = -1;
      for (let i = 0; i < length; i++) {
        if (view.getUint8(dataStart + i) === 0) { sep = i; break; }
      }
      if (sep > 0) {
        const key = readAscii(view, dataStart, sep);
        const val = readAscii(view, dataStart + sep + 1, length - sep - 1);
        if (key && val) result.tags[key] = val.slice(0, 220);
      } else if (raw) {
        result.tags.ComentarioPNG = raw.slice(0, 220);
      }
    } else if (type === 'IEND') {
      break;
    }
    offset += 12 + length;
  }
  return result;
}

export async function parseImageMetadata(file) {
  const buffer = await file.arrayBuffer();
  const view = new DataView(buffer);
  let parsed = { format: 'Desconhecido', tags: {}, gps: null, dimensions: null };

  if (view.byteLength >= 4 && view.getUint16(0, false) === 0xffd8) {
    parsed = parseJpegExif(view);
  } else if (view.byteLength >= 8 && view.getUint32(0, false) === 0x89504e47) {
    parsed = parsePngMetadata(view);
  }

  const alerts = [];
  if (parsed.gps) alerts.push('Coordenadas GPS exatas expostas nos metadados (alto risco de privacidade).');
  if (parsed.tags.Software) alerts.push(`Software de edicao/geracao detectado: ${parsed.tags.Software}`);
  if (parsed.tags.NumeroSerieCamera || parsed.tags.ProprietarioCamera) {
    alerts.push('Identificador unico de equipamento/proprietario presente no cabecalho EXIF.');
  }

  return {
    filename: file.name,
    size: file.size,
    mimeType: file.type || 'image/*',
    lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : null,
    ...parsed,
    alerts
  };
}
