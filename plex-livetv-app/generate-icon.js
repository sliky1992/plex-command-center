// Generate a simple PNG icon for the app
const fs = require('fs');
const zlib = require('zlib');

function createPNG(size) {
  const w = size, h = size;
  const px = Buffer.alloc(w * h * 4);

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      const cx = x / w, cy = y / h;

      // Background gradient
      const t = (cx + cy) / 2;
      px[i] = Math.round(10 + 30 * t);     // R
      px[i+1] = Math.round(14 + 20 * t);   // G
      px[i+2] = Math.round(39 + 50 * t);   // B
      px[i+3] = 255;

      // TV shape
      const tvL = 0.15, tvR = 0.85, tvT = 0.2, tvB = 0.75;
      if (cx > tvL && cx < tvR && cy > tvT && cy < tvB) {
        // TV border
        const borderW = 0.03;
        if (cx < tvL + borderW || cx > tvR - borderW || cy < tvT + borderW || cy > tvB - borderW) {
          px[i] = 59; px[i+1] = 130; px[i+2] = 246;
        } else {
          // Screen - dark
          px[i] = 15; px[i+1] = 23; px[i+2] = 42;

          // Play triangle
          const scX = (cx - tvL - borderW) / (tvR - tvL - 2*borderW);
          const scY = (cy - tvT - borderW) / (tvB - tvT - 2*borderW);
          const triCx = 0.45, triCy = 0.5;
          const triSize = 0.25;
          const dx = scX - triCx, dy = scY - triCy;
          if (dx > -triSize && dx < triSize && Math.abs(dy) < (triSize - dx) * 0.6) {
            px[i] = 139; px[i+1] = 92; px[i+2] = 246;
          }
        }
      }

      // Stand
      if (cy > 0.75 && cy < 0.85) {
        if (cx > 0.4 && cx < 0.6) {
          px[i] = 59; px[i+1] = 130; px[i+2] = 246;
        }
      }
      if (cy >= 0.85 && cy < 0.9) {
        if (cx > 0.3 && cx < 0.7) {
          px[i] = 59; px[i+1] = 130; px[i+2] = 246;
        }
      }
    }
  }

  // Build PNG
  const raw = Buffer.alloc(h * (1 + w * 4));
  for (let y = 0; y < h; y++) {
    raw[y * (1 + w * 4)] = 0;
    px.copy(raw, y * (1 + w * 4) + 1, y * w * 4, (y + 1) * w * 4);
  }

  const compressed = zlib.deflateSync(raw);
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const tb = Buffer.from(type);
    const cb = Buffer.concat([tb, data]);
    const tbl = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      tbl[i] = c;
    }
    let crc = -1;
    for (let i = 0; i < cb.length; i++) crc = tbl[(crc ^ cb[i]) & 0xFF] ^ (crc >>> 8);
    crc = (crc ^ -1) >>> 0;
    const crcB = Buffer.alloc(4);
    crcB.writeUInt32BE(crc);
    return Buffer.concat([len, tb, data, crcB]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6;

  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', compressed), chunk('IEND', Buffer.alloc(0))]);
}

fs.writeFileSync('icon.png', createPNG(256));
console.log('icon.png generated');
