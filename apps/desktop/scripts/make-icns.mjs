import fs from 'node:fs/promises'
import path from 'node:path'

const pad4 = (value) => (value + 3) & ~3

const writeChunk = (type, data) => {
  const paddedLength = pad4(data.length)
  const padded = paddedLength === data.length ? data : Buffer.concat([data, Buffer.alloc(paddedLength - data.length)])
  const chunk = Buffer.alloc(8)
  chunk.write(type, 0, 'ascii')
  chunk.writeUInt32BE(8 + padded.length, 4)
  return Buffer.concat([chunk, padded])
}

const main = async () => {
  const args = process.argv.slice(2)
  if (args.length < 2) {
    console.error('Usage: node scripts/make-icns.mjs <input-dir> <output-file>')
    process.exit(2)
  }

  const [inputDir, outputFile] = args
  const chunks = [
    { type: 'icp4', file: 'icon_16.png' },
    { type: 'icp5', file: 'icon_32.png' },
    { type: 'icp6', file: 'icon_64.png' },
    { type: 'ic07', file: 'icon_128.png' },
    { type: 'ic08', file: 'icon_256.png' },
    { type: 'ic09', file: 'icon_512.png' },
    { type: 'ic10', file: 'icon_1024.png' }
  ]

  const parts = []
  for (const chunk of chunks) {
    const data = await fs.readFile(path.join(inputDir, chunk.file))
    parts.push(writeChunk(chunk.type, data))
  }

  const totalSize = 8 + parts.reduce((sum, part) => sum + part.length, 0)
  const header = Buffer.alloc(8)
  header.write('icns', 0, 'ascii')
  header.writeUInt32BE(totalSize, 4)

  await fs.writeFile(outputFile, Buffer.concat([header, ...parts]))
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
