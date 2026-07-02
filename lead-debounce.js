#!/usr/bin/env node

// =============================================================
//  lead‑debounce – Red Team Email Validation Framework
//  FOR AUTHORIZED TESTING ONLY – UNAUTHORIZED USE IS ILLEGAL
// =============================================================

const fs = require('fs');
const readline = require('readline');
const dns = require('dns').promises;
const net = require('net');
const figlet = require('figlet');
const chalk = require('chalk');
const { SocksProxyAgent } = require('socks-proxy-agent'); // optional

// ---- Safety switch ----
if (process.env.REDTEAM_MODE !== '1') {
    console.error(chalk.red('❌ REDTEAM_MODE is not set. This tool is for authorised use only.'));
    console.error(chalk.yellow('   Set REDTEAM_MODE=1 to proceed.'));
    process.exit(1);
}

// ---- Configurable settings ----
const CONFIG_FILE = './lead-debounce-config.json';

let config = {
    concurrency: 10,
    proxyFile: null,
    timeout: 25000,
    debug: false,
    telegramEnabled: false,
    telegramBotToken: '',
    telegramChatId: '',
    targets: [],
    results: []
};

// ---- Load / save config ----
function loadConfig() {
    try {
        const data = fs.readFileSync(CONFIG_FILE, 'utf8');
        config = { ...config, ...JSON.parse(data) };
    } catch (_) { /* no config yet */ }
}

function saveConfig() {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// ---- Generate beautiful banner with figlet ----
function showBanner() {
    return new Promise((resolve) => {
        figlet.text('lead-debounce', { font: 'Small' }, (err, data) => {
            if (err) {
                // Fallback ASCII if figlet fails
                console.log(chalk.cyan('lead-debounce'));
                resolve();
                return;
            }
            // Gradient from cyan to magenta
            const lines = data.split('\n');
            const colors = [chalk.cyan, chalk.blue, chalk.magenta];
            lines.forEach((line, i) => {
                const color = colors[i % colors.length];
                console.log(color(line));
            });
            // Version and author
            console.log(chalk.green('------------------------------------------'));
            console.log(chalk.yellow(' Version 1.0.0'));
            console.log(chalk.yellow(' Author : </>'));
            console.log(chalk.green('------------------------------------------'));
            console.log(chalk.red.bold('  FOR AUTHORIZED TESTING ONLY!'));
            console.log(chalk.red('  Unauthorized use is a FEDERAL CRIME.'));
            console.log(chalk.green('------------------------------------------'));
            resolve();
        });
    });
}

// ---- Helper to show menu ----
async function showMenu() {
    console.clear();
    await showBanner();
    console.log(`\n${chalk.yellow('[ MAIN MENU ]')}`);
    console.log(`  ${chalk.cyan('1.')} Load targets from file`);
    console.log(`  ${chalk.cyan('2.')} Add single target`);
    console.log(`  ${chalk.cyan('3.')} Set concurrency (current: ${config.concurrency})`);
    console.log(`  ${chalk.cyan('4.')} Set proxy list (current: ${config.proxyFile || 'none'})`);
    console.log(`  ${chalk.cyan('5.')} Toggle debug mode (${config.debug ? 'ON' : 'OFF'})`);
    console.log(`  ${chalk.cyan('6.')} Run validation (${config.targets.length} targets loaded)`);
    console.log(`  ${chalk.cyan('7.')} Export results`);
    console.log(`  ${chalk.cyan('8.')} Configure Telegram notifications (stub)`);
    console.log(`  ${chalk.cyan('9.')} Clean logs (post‑exploit)`);
    console.log(`  ${chalk.cyan('0.')} Exit`);
    console.log(chalk.gray('─────────────────────────────────────────────────────'));
}

// ---- Validation engine (same as before, but uses config) ----
const mxCache = new Map();
const catchAllCache = new Map();
const MAX_RETRIES = 3;

function isValidSyntax(email) {
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

async function getMxRecords(domain) {
    if (mxCache.has(domain)) return mxCache.get(domain);
    try {
        const records = await dns.resolveMx(domain);
        records.sort((a, b) => a.priority - b.priority);
        mxCache.set(domain, records);
        return records;
    } catch (_) { return []; }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function validateMailboxDirect(email, mxRecords, retries = 0) {
    return new Promise((resolve) => {
        const domain = email.split('@')[1];
        if (!mxRecords.length) return resolve(false);
        const mx = mxRecords[0];
        const host = mx.exchange;

        const socket = net.createConnection({ host, port: 25, timeout: config.timeout });
        let buffer = '';
        let resolved = false;
        let step = 0;
        let timeoutId;

        const cleanup = () => { clearTimeout(timeoutId); if (!socket.destroyed) socket.destroy(); };
        const finish = (result) => { if (resolved) return; resolved = true; cleanup(); resolve(result); };

        timeoutId = setTimeout(() => { finish(false); }, config.timeout);

        socket.on('data', (data) => {
            buffer += data.toString();
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            for (const line of lines) {
                const trimmed = line.trim();
                if (config.debug) console.log(chalk.gray(`[${email}] << ${trimmed}`));
                if (step === 0 && /^220/.test(trimmed)) {
                    step = 1;
                    socket.write(`EHLO mail.${domain}\r\n`);
                    if (config.debug) console.log(chalk.gray(`[${email}] >> EHLO mail.${domain}`));
                } else if (step === 1 && /^250/.test(trimmed)) {
                    step = 2;
                    socket.write(`MAIL FROM:<postmaster@${domain}>\r\n`);
                    if (config.debug) console.log(chalk.gray(`[${email}] >> MAIL FROM:<postmaster@${domain}>`));
                } else if (step === 2 && /^250/.test(trimmed)) {
                    step = 3;
                    socket.write(`RCPT TO:<${email}>\r\n`);
                    if (config.debug) console.log(chalk.gray(`[${email}] >> RCPT TO:<${email}>`));
                } else if (step === 3) {
                    if (/^250/.test(trimmed)) {
                        finish(true);
                    } else if (/^5[0-9]{2}/.test(trimmed) || /^553/.test(trimmed)) {
                        if (/Spamhaus/i.test(trimmed)) console.warn(chalk.yellow(`[${email}] Spamhaus block`));
                        finish(false);
                    } else if (/^4[0-9]{2}/.test(trimmed) || /^421/.test(trimmed)) {
                        if (retries < MAX_RETRIES) {
                            cleanup();
                            setTimeout(async () => {
                                const res = await validateMailboxDirect(email, mxRecords, retries + 1);
                                resolve(res);
                            }, 2000 * (retries + 1));
                            return;
                        } else finish(false);
                    } else finish(false);
                }
            }
        });
        socket.on('error', () => finish(false));
        socket.on('close', () => { if (!resolved) finish(false); });
    });
}

async function isCatchAllDomain(domain, mxRecords) {
    if (catchAllCache.has(domain)) return catchAllCache.get(domain);
    const randomLocal = `test-${Math.random().toString(36).substring(2, 10)}@${domain}`;
    const result = await validateMailboxDirect(randomLocal, mxRecords);
    catchAllCache.set(domain, result);
    return result;
}

async function validateEmail(email) {
    if (!isValidSyntax(email)) return { email, status: 'invalid_syntax' };
    const domain = email.split('@')[1];
    const mx = await getMxRecords(domain);
    if (!mx.length) return { email, status: 'no_mx' };
    const isCatchAll = await isCatchAllDomain(domain, mx);
    if (isCatchAll) return { email, status: 'catch_all' };
    const valid = await validateMailboxDirect(email, mx);
    return { email, status: valid ? 'valid' : 'invalid' };
}

async function runValidation() {
    if (!config.targets.length) {
        console.log(chalk.red('No targets loaded! Use option 1 or 2.'));
        return;
    }
    console.log(chalk.yellow(`Starting validation of ${config.targets.length} emails with concurrency ${config.concurrency}...`));
    const start = Date.now();
    const queue = [...config.targets];
    const results = [];
    const workers = [];

    async function worker() {
        while (queue.length) {
            const email = queue.shift();
            console.log(chalk.cyan(`🔄 ${email}`));
            const res = await validateEmail(email);
            results.push(res);
            await sleep(300 + Math.random() * 500);
        }
    }

    for (let i = 0; i < config.concurrency; i++) workers.push(worker());
    await Promise.all(workers);

    config.results = results;
    const valid = results.filter(r => r.status === 'valid' || r.status === 'catch_all');
    const invalid = results.filter(r => r.status !== 'valid' && r.status !== 'catch_all');
    console.log(chalk.green(`Done in ${((Date.now()-start)/1000).toFixed(1)}s. Valid: ${valid.length}, Invalid: ${invalid.length}`));
    saveConfig();
}

// ---- CLI interaction ----
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function prompt(question) {
    return new Promise(resolve => rl.question(question, resolve));
}

async function main() {
    loadConfig();
    let exit = false;

    while (!exit) {
        await showMenu();
        const choice = await prompt('Select: ');
        switch (choice.trim()) {
            case '1': {
                const file = await prompt('Enter path to email list: ');
                try {
                    const data = fs.readFileSync(file, 'utf8');
                    const emails = data.split('\n').map(e => e.trim()).filter(Boolean);
                    config.targets = emails;
                    saveConfig();
                    console.log(chalk.green(`Loaded ${emails.length} targets.`));
                } catch (e) { console.error(chalk.red('Error reading file.')); }
                break;
            }
            case '2': {
                const email = await prompt('Enter email address: ');
                if (email && isValidSyntax(email)) {
                    config.targets.push(email);
                    saveConfig();
                    console.log(chalk.green(`Added ${email}.`));
                } else console.log(chalk.red('Invalid email syntax.'));
                break;
            }
            case '3': {
                const c = await prompt(`Enter concurrency (1-50, current ${config.concurrency}): `);
                const num = parseInt(c);
                if (num >= 1 && num <= 50) { config.concurrency = num; saveConfig(); console.log(chalk.green('Updated.')); }
                else console.log(chalk.red('Invalid number.'));
                break;
            }
            case '4': {
                const file = await prompt('Enter proxy list file path (or blank to disable): ');
                if (file.trim()) {
                    try { fs.accessSync(file); config.proxyFile = file; saveConfig(); console.log(chalk.green('Proxy file set.')); }
                    catch { console.log(chalk.red('File not found.')); }
                } else { config.proxyFile = null; saveConfig(); console.log(chalk.green('Proxies disabled.')); }
                break;
            }
            case '5': {
                config.debug = !config.debug;
                saveConfig();
                console.log(chalk.green(`Debug mode ${config.debug ? 'ON' : 'OFF'}.`));
                break;
            }
            case '6': {
                await runValidation();
                break;
            }
            case '7': {
                if (!config.results.length) { console.log(chalk.red('No results. Run validation first.')); break; }
                const valid = config.results.filter(r => r.status === 'valid' || r.status === 'catch_all').map(r => r.email);
                const invalid = config.results.filter(r => r.status !== 'valid' && r.status !== 'catch_all').map(r => r.email);
                fs.writeFileSync('valid_emails.txt', valid.join('\n'));
                fs.writeFileSync('invalid_emails.txt', invalid.join('\n'));
                fs.writeFileSync('results.json', JSON.stringify(config.results, null, 2));
                console.log(chalk.green('Results exported to valid_emails.txt, invalid_emails.txt, results.json'));
                break;
            }
            case '8': {
                console.log(chalk.yellow('Telegram C2 stub – implement your own token/chatID in config.'));
                // Extend here
                break;
            }
            case '9': {
                try { fs.unlinkSync('valid_emails.txt'); } catch (_) {}
                try { fs.unlinkSync('invalid_emails.txt'); } catch (_) {}
                try { fs.unlinkSync('results.json'); } catch (_) {}
                config.results = [];
                saveConfig();
                console.log(chalk.green('Logs cleaned.'));
                break;
            }
            case '0':
                exit = true;
                break;
            default:
                console.log(chalk.red('Invalid option.'));
        }
        if (!exit) await prompt('Press Enter to continue...');
    }
    rl.close();
    process.exit(0);
}

main().catch(console.error);