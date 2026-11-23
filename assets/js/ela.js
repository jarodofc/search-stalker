function loadImageFromBlob(blob) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.addEventListener('load', () => {
      URL.revokeObjectURL(url);
      resolve(img);
    });
    img.addEventListener('error', () => {
      URL.revokeObjectURL(url);
      reject(new Error('Nao foi possivel decodificar a imagem selecionada.'));
    });
    img.src = url;
  });
}

function canvasToJpegBlob(canvas, quality) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) reject(new Error('Falha ao recomprimir imagem para JPEG.'));
      else resolve(blob);
    }, 'image/jpeg', quality);
  });
}

export async function runErrorLevelAnalysis(file, options = {}) {
  const quality = Math.min(0.99, Math.max(0.5, (options.quality || 90) / 100));
  const scale = Math.min(40, Math.max(1, options.scale || 15));

  const originalImg = await loadImageFromBlob(file);
  const maxDim = 1600;
  let width = originalImg.naturalWidth || originalImg.width;
  let height = originalImg.naturalHeight || originalImg.height;
  if (width > maxDim || height > maxDim) {
    const ratio = Math.min(maxDim / width, maxDim / height);
    width = Math.max(1, Math.round(width * ratio));
    height = Math.max(1, Math.round(height * ratio));
  }

  const origCanvas = document.createElement('canvas');
  origCanvas.width = width;
  origCanvas.height = height;
  const origCtx = origCanvas.getContext('2d', { willReadFrequently: true });
  origCtx.drawImage(originalImg, 0, 0, width, height);
  const origData = origCtx.getImageData(0, 0, width, height);

  const recompressedBlob = await canvasToJpegBlob(origCanvas, quality);
  const recompImg = await loadImageFromBlob(recompressedBlob);

  const recompCanvas = document.createElement('canvas');
  recompCanvas.width = width;
  recompCanvas.height = height;
  const recompCtx = recompCanvas.getContext('2d', { willReadFrequently: true });
  recompCtx.drawImage(recompImg, 0, 0, width, height);
  const recompData = recompCtx.getImageData(0, 0, width, height);

  const elaCanvas = document.createElement('canvas');
  elaCanvas.width = width;
  elaCanvas.height = height;
  const elaCtx = elaCanvas.getContext('2d');
  const outImg = elaCtx.createImageData(width, height);

  const a = origData.data;
  const b = recompData.data;
  const out = outImg.data;
  const pixelCount = width * height;

  let sumDiff = 0;
  let maxDiff = 0;
  let highDiffPixels = 0;

  for (let i = 0; i < a.length; i += 4) {
    const dr = Math.abs(a[i] - b[i]);
    const dg = Math.abs(a[i + 1] - b[i + 1]);
    const db = Math.abs(a[i + 2] - b[i + 2]);
    const avg = (dr + dg + db) / 3;
    sumDiff += avg;
    if (avg > maxDiff) maxDiff = avg;
    if (avg >= 18) highDiffPixels++;

    out[i] = Math.min(255, Math.round(dr * scale));
    out[i + 1] = Math.min(255, Math.round(dg * scale));
    out[i + 2] = Math.min(255, Math.round(db * scale));
    out[i + 3] = 255;
  }

  elaCtx.putImageData(outImg, 0, 0);

  const meanError = Number((sumDiff / pixelCount).toFixed(2));
  const highPct = Number(((highDiffPixels / pixelCount) * 100).toFixed(2));
  let interpretation = 'Distribuicao de erro uniforme (sem anomalias grosseiras evidentes).';
  if (highPct > 12 || meanError > 12) {
    interpretation = 'Alto nivel de variancia residual: verifique regioes muito brilhantes isoladas (possiveis insercoes/edicoes ou PNG original sem compressao previa).';
  } else if (highPct > 4) {
    interpretation = 'Variancia moderada: inspecione visualmente bordas e blocos com brilho discrepante do fundo.';
  }

  return {
    width,
    height,
    qualityPct: Math.round(quality * 100),
    scale,
    originalDataUrl: origCanvas.toDataURL('image/png'),
    elaDataUrl: elaCanvas.toDataURL('image/png'),
    stats: {
      meanError,
      maxError: Number(maxDiff.toFixed(2)),
      highVariancePct: highPct,
      interpretation
    }
  };
}
