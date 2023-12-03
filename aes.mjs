// aes encryption by nodejs

import fs from 'node:fs';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const ALG_ENCRYPT = 'aes-256-cbc';
const ALG_HASH = 'sha256';
const KEY_LENGTH = 32;
const MIN_ITERATIONS = 999999;

// password: Buffer
// salt: Buffer
// return Buffer(32 bytes)
function createPbkdf2(password, salt, iterations) {
    return crypto.pbkdf2Sync(password, salt, iterations, KEY_LENGTH, ALG_HASH);
}

// key: Buffer
// data: Buffer
// return Buffer(32 bytes)
function hmacSha256(key, data) {
    const h = crypto.createHmac(ALG_HASH, key);
    h.update(data);
    return h.digest();
}

// key: buffer(32 bytes)
// iv: buffer(16 bytes)
// data: buffer
// return: buffer
function encrypt(key, iv, data) {
    const cipher = crypto.createCipheriv(ALG_ENCRYPT, key, iv);
    cipher.setAutoPadding(true);
    let r1 = cipher.update(data);
    let r2 = cipher.final();
    return Buffer.concat([r1, r2]);
}

// key: buffer(32 bytes)
// iv: buffer(16 bytes)
// data: buffer
// return: buffer
function decrypt(key, iv, data) {
    const cipher = crypto.createDecipheriv(ALG_ENCRYPT, key, iv);
    cipher.setAutoPadding(true);
    let r1 = cipher.update(data);
    let r2 = cipher.final();
    return Buffer.concat([r1, r2]);
}

function randomString(size) {
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let s = '';
    for (let i = 0; i < size; i++) {
        let n = Math.floor(Math.random() * chars.length);
        s += chars.substring(n, n + 1);
    }
    return s;
}

async function tests() {
    console.log('start 10 tests...');
    let failed = 0;
    for (let i = 0; i < 10; i++) {
        let ok = await test();
        if (!ok) {
            failed++;
        }
    }
    if (failed > 0) {
        console.error(`ERROR: ${failed} tests.`);
    } else {
        console.log('tests ok.');
    }
    return failed;
}

async function test() {
    console.log('---------- start test ----------');
    const words = [
        'about', 'actual', 'add', 'answer', 'append', 'array',
        'before', 'between', 'blue', 'browser', 'build', 'chain',
        'code', 'color', 'command', 'comment', 'compress', 'compute',
        'console', 'copy', 'correct', 'different', 'double', 'down',
        'each', 'easy', 'edit', 'example', 'explain', 'extend',
        'factor', 'feed', 'fill', 'float', 'forward', 'free',
        'function', 'green', 'head', 'hello', 'ice', 'input',
        'insert', 'integer', 'just', 'key', 'length', 'less',
        'library', 'link', 'long', 'loop', 'many', 'mapping',
        'more', 'move', 'node', 'other', 'output', 'paper',
        'paste', 'photo', 'program', 'push', 'question', 'read',
        'registry', 'remove', 'result', 'return', 'rock', 'save',
        'scale', 'search', 'self', 'shell', 'shift', 'short',
        'show', 'shuffle', 'size', 'space', 'spark', 'start',
        'store', 'style', 'team', 'unit', 'user', 'value',
        'version', 'view', 'watch', 'while', 'wood', 'work',
        'world', 'write', 'yellow', 'zoo'
    ];
    // shuffle:
    for (let i = words.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [words[i], words[j]] = [words[j], words[i]];
    }
    const message = words.splice(0, 25).join(' ');
    console.log(`message (${message.length}): ${message}`);
    const password = randomString(8 + Math.floor(Math.random() * 10));
    console.log(`password: ${password}`);

    // encrypt:
    const pbkdf2Salt = crypto.randomBytes(32);
    const iterations = MIN_ITERATIONS + crypto.randomInt(999999);
    const pbk = createPbkdf2(password, pbkdf2Salt, iterations);
    console.log(`pbk: ${pbk.toString('hex')}`);
    const obj = doEncrypt(pbk, Buffer.from(message, 'utf8'));
    obj['pbkdf2-salt'] = pbkdf2Salt.toString('hex');
    obj['pbkdf2-iterations'] = iterations;

    console.log(`encrypted iv: ${obj['encrypt-iv'].toString('hex')}`);
    console.log(`encrypted data: ${obj['encrypt-data'].toString('hex')}`);

    // decrypt:
    const decrypted = doDecrypt(password, obj);

    return decrypted.toString('utf8') === message;
}

function usage(error) {
    if (error) {
        console.error(error);
    }
    console.log(`Encrypt:
    node aes.mjs encrypt <save-to-json-file>
Decrypt:
    node aes.mjs decrypt <read-from-json-file>
Run test:
    node aes.mjs test`);
}

function checkPassword(s) {
    if (s.length < 8) {
        return 'password must be at least 8 chars.';
    }
    if (s.length > 30) {
        return 'password must be at most 30 chars.';
    }
    for (let i = 0; i < s.length; i++) {
        let n = s.charCodeAt(i);
        if (n < 32 || n > 126) {
            return 'password must not contains non-printable chars.';
        }
    }
    return '';
}

function doEncrypt(pbk, message) {
    const iv = crypto.randomBytes(16);
    // hmac-hash the message AND iv for better privacy:
    const messageIvHmac = hmacSha256(iv, message);
    const enc = encrypt(pbk, iv, message);
    return {
        'hash-alg': ALG_HASH,
        'message-iv-hmac': messageIvHmac.toString('hex'),
        'encrypt-alg': ALG_ENCRYPT,
        'encrypt-iv': iv.toString('hex'),
        'encrypt-data': enc.toString('hex')
    };
}

function doDecrypt(password, obj) {
    const
        pbkdf2Salt = Buffer.from(obj['pbkdf2-salt'], 'hex'),
        encryptIv = Buffer.from(obj['encrypt-iv'], 'hex'),
        encryptData = Buffer.from(obj['encrypt-data'], 'hex'),
        pbkdf2Iterations = obj['pbkdf2-iterations'];
    const pbk = createPbkdf2(password, pbkdf2Salt, pbkdf2Iterations);
    return decrypt(pbk, encryptIv, encryptData);
}

async function doInputPassword() {
    const rl = readline.createInterface({ input, output });
    let password = await rl.question('password: ');
    rl.close();
    return password;
}

async function doInputPasswordAndMessage() {
    const rl = readline.createInterface({ input, output });
    let password;
    for (; ;) {
        password = await rl.question('password: ');
        let err = checkPassword(password);
        if (err) {
            console.error(err);
        } else {
            break;
        }
    }
    let msgs = [];
    console.log('type messages (type EOF to end):');
    for (; ;) {
        let s = await rl.question('');
        if (s === 'EOF') {
            break;
        }
        msgs.push(s);
    }
    rl.close();
    return [password, msgs.join('\n')];
}

async function main() {
    const [, , cmd, file] = process.argv;

    if (cmd === 'test') {
        return await tests();
    }

    if (cmd === 'encrypt') {
        if (file === undefined) {
            usage('Error: missing file name.');
            return 1;
        }
        if (fs.existsSync(file)) {
            usage('Error: file already exist.');
            return 1;
        }
        const [password, message] = await doInputPasswordAndMessage();
        const pbkdf2Salt = crypto.randomBytes(32);
        const iterations = MIN_ITERATIONS + crypto.randomInt(999999);
        const pbk = createPbkdf2(password, pbkdf2Salt, iterations);
        let obj = doEncrypt(pbk, Buffer.from(message, 'utf8'));
        obj['pbkdf2-salt'] = pbkdf2Salt.toString('hex');
        obj['pbkdf2-iterations'] = iterations;
        const json = JSON.stringify(obj, null, '  ');
        fs.writeFileSync(file, json, { encoding: 'utf8' });
        console.log(`encrypted data saved: ${file}\n` + json);
        return 0;
    }

    if (cmd === 'decrypt') {
        if (file === undefined) {
            usage('Error: missing file name.');
            return 1;
        }
        if (!fs.existsSync(file)) {
            usage('Error: file not exist.');
            return 1;
        }
        const
            json = fs.readFileSync(file, { encoding: 'utf8' }),
            obj = JSON.parse(json),
            hashAlg = obj['hash-alg'],
            encryptAlg = obj['encrypt-alg'],
            messageIvHmac = obj['message-iv-hmac'],
            encryptIv = Buffer.from(obj['encrypt-iv'], 'hex');
        if (hashAlg !== ALG_HASH) {
            console.error(`invalid hash-alg: ${hashAlg}`);
            return 1;
        }
        if (encryptAlg !== ALG_ENCRYPT) {
            console.error(`invalid encrypt-alg: ${encryptAlg}`);
            return 1;
        }
        const password = await doInputPassword();
        const msgData = doDecrypt(password, obj);
        // check message-iv-hmac:
        const hash = hmacSha256(encryptIv, msgData);
        if (hash.toString('hex') !== messageIvHmac) {
            console.error('message-iv-hmac check failed!');
            return 1;
        }
        console.log('Decrypted ok:');
        console.log(msgData.toString('utf8'));
        return 0;
    }

    usage();
    return 1;
}

main().then(code => process.exit(code));
