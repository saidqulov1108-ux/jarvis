
import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'
import {
  mkdir,
  readFile,
  rename,
  writeFile,
  lstat,
} from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

const DEFAULT_FILE = join(homedir(), '.jarvis', 'devices.json')
const PAIRING_TTL_MS = 5 * 60 * 1000

const hashToken = (token) =>
  createHash('sha256').update(token).digest('hex')

const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length &&
    timingSafeEqual(left, right)
}

export function createDeviceAuth({ filePath = DEFAULT_FILE } = {}) {
  const pending = new Map()
  let queue = Promise.resolve()

  async function load() {
    await mkdir(dirname(filePath), { recursive: true, mode: 0o700 })

    try {
      const info = await lstat(filePath)
      if (!info.isFile() || info.isSymbolicLink()) {
        throw new Error('Device store must be a regular file')
      }

      const data = JSON.parse(await readFile(filePath, 'utf8'))
      if (data.version !== 1 || !Array.isArray(data.devices)) {
        throw new Error('Invalid device store format')
      }

      return data.devices
    } catch (error) {
      if (error.code === 'ENOENT') return []
      throw error
    }
  }

  async function save(devices) {
    await mkdir(dirname(filePath), { recursive: true, mode: 0o700 })

    const temp = `${filePath}.${randomBytes(8).toString('hex')}.tmp`

    try {
      await writeFile(
        temp,
        JSON.stringify({ version: 1, devices }, null, 2),
        { encoding: 'utf8', mode: 0o600, flag: 'wx' },
      )
      await rename(temp, filePath)
    } catch (error) {
      const { unlink } = await import('node:fs/promises')
      await unlink(temp).catch(() => {})
      throw error
    }
  }

  function serial(operation) {
    const result = queue.then(operation)
    queue = result.catch(() => {})
    return result
  }

  function createPairingRequest({ label = 'New device' } = {}) {
    const id = randomBytes(24).toString('base64url')

    pending.set(id, {
      label: String(label).slice(0, 80),
      expiresAt: Date.now() + PAIRING_TTL_MS,
    })

    return {
      requestId: id,
      expiresInSeconds: PAIRING_TTL_MS / 1000,
    }
  }

  async function approvePairing(requestId) {
    return serial(async () => {
      const request = pending.get(requestId)
      pending.delete(requestId)

      if (!request || request.expiresAt < Date.now()) {
        throw new Error('Pairing request expired or not found')
      }

      const devices = await load()
      const token = `jv1_${randomBytes(32).toString('base64url')}`

      const device = {
        id: randomBytes(16).toString('hex'),
        label: request.label,
        tokenHash: hashToken(token),
        createdAt: new Date().toISOString(),
        revokedAt: null,
      }

      devices.push(device)
      await save(devices)

      // Show this token to the owner ONCE.
      return {
        deviceId: device.id,
        label: device.label,
        token,
      }
    })
  }

  async function authenticate(token) {
    if (
      typeof token !== 'string' ||
      !/^jv1_[A-Za-z0-9_-]{40,60}$/.test(token)
    ) {
      return null
    }

    const devices = await load()
    const candidate = hashToken(token)

    const device = devices.find(
      (item) =>
        !item.revokedAt &&
        safeEqual(item.tokenHash, candidate),
    )

    if (!device) return null

    return {
      id: device.id,
      label: device.label,
      createdAt: device.createdAt,
    }
  }

  async function revokeDevice(deviceId) {
    return serial(async () => {
      const devices = await load()
      const device = devices.find((item) => item.id === deviceId)

      if (!device || device.revokedAt) return false

      device.revokedAt = new Date().toISOString()
      await save(devices)
      return true
    })
  }

  async function listDevices() {
    const devices = await load()

    return devices.map(({ id, label, createdAt, revokedAt }) => ({
      id,
      label,
      createdAt,
      revokedAt,
      active: !revokedAt,
    }))
  }

  return {
    createPairingRequest,
    approvePairing,
    authenticate,
    revokeDevice,
    listDevices,
  }
}
