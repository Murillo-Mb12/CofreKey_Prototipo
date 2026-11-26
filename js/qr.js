/*
 * CofreKey — leitura e geração de QR codes
 *
 * Leitura: usa o BarcodeDetector do navegador quando existe (Chrome/Android)
 * e, nos demais, a biblioteca jsQR (vendor/jsQR.min.js). Tudo roda no aparelho:
 * nenhuma imagem sai dele.
 * Geração: biblioteca QRCode.js (vendor/qrcode.min.js).
 */
(function (root) {
  'use strict';

  let detector = null;
  async function getDetector() {
    if (detector !== null) return detector;
    detector = false;
    try {
      if ('BarcodeDetector' in root) {
        const formats = await root.BarcodeDetector.getSupportedFormats();
        if (formats.includes('qr_code')) detector = new root.BarcodeDetector({ formats: ['qr_code'] });
      }
    } catch (e) { detector = false; }
    return detector;
  }

  async function decodeSource(source, width, height, canvas) {
    const det = await getDetector();
    if (det) {
      try {
        const found = await det.detect(source);
        if (found.length) return found[0].rawValue;
      } catch (e) { /* tenta com o jsQR */ }
    }
    if (!root.jsQR) return null;
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(source, 0, 0, width, height);
    const img = ctx.getImageData(0, 0, width, height);
    const res = root.jsQR(img.data, width, height, { inversionAttempts: 'attemptBoth' });
    return res ? res.data : null;
  }

  /** Lê um QR code de uma imagem (print da tela, foto). Devolve o texto ou null. */
  async function decodeFile(file) {
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    const w = Math.round(bitmap.width * scale), h = Math.round(bitmap.height * scale);
    const canvas = document.createElement('canvas');
    try {
      return await decodeSource(bitmap, w, h, canvas);
    } finally {
      if (bitmap.close) bitmap.close();
    }
  }

  /**
   * Abre a câmera traseira no <video> e chama onResult(texto) quando encontrar um QR code.
   * Devolve uma função para desligar a câmera. Lança 'NO_CAMERA' se não houver câmera ou permissão.
   */
  async function startCamera(video, onResult) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) throw new Error('NO_CAMERA');
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    } catch (e) {
      throw new Error(e && e.name === 'NotAllowedError' ? 'CAMERA_DENIED' : 'NO_CAMERA');
    }
    video.srcObject = stream;
    video.setAttribute('playsinline', '');
    video.muted = true;
    await video.play().catch(() => {});
    const canvas = document.createElement('canvas');
    let stopped = false, busy = false;
    const timer = setInterval(async () => {
      if (stopped || busy || video.readyState < 2) return;
      busy = true;
      try {
        const scale = Math.min(1, 720 / Math.max(video.videoWidth, video.videoHeight));
        const text = await decodeSource(video, Math.round(video.videoWidth * scale), Math.round(video.videoHeight * scale), canvas);
        if (text && !stopped) onResult(text);
      } catch (e) { /* tenta no próximo quadro */ }
      busy = false;
    }, 250);
    return function stop() {
      stopped = true;
      clearInterval(timer);
      stream.getTracks().forEach((t) => t.stop());
      video.srcObject = null;
    };
  }

  /** Desenha um QR code dentro do elemento. */
  function render(container, text) {
    container.textContent = '';
    if (!root.QRCode) {
      container.textContent = 'Não foi possível gerar o QR code.';
      return;
    }
    // eslint-disable-next-line no-new
    new root.QRCode(container, { text, width: 208, height: 208, correctLevel: root.QRCode.CorrectLevel.M });
  }

  (root.CK = root.CK || {}).qr = { decodeFile, startCamera, render };
})(self);
