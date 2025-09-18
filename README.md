# Worm Scanner for Shai-Hulud NPM Attack

A lightweight, zero-dependency Node.js tool to scan your projects for compromised packages from the Shai-Hulud npm supply-chain attack.

## What is the Shai-Hulud Attack?

The Shai-Hulud attack is a sophisticated npm supply-chain attack that compromised multiple popular packages. The malicious code in these packages attempts to steal credentials, tokens, and other sensitive information from developer environments.

## Features

- **Zero Dependencies**: Single JavaScript file with no external dependencies
- **Multiple Advisory Sources**: Fetches data from several security advisories
- **Semver Range Detection**: Detects vulnerable packages even when using version ranges (`~1.2.0`, `^1.2.0`, etc.)
- **Package Lock Support**: Scans both package.json and package-lock.json, including nested dependencies
- **Offline Scanning**: Once data is fetched, scanning can be done offline
- **Fast & Efficient**: Parallel requests to advisory sources with proper error handling

## How to Use

Simply copy the `scan.js` file to your project directory and run it:

```bash
node scan.js
```

That's it! The scanner will:

1. Fetch compromised package data from security advisories
2. Check your project's package.json and package-lock.json files
3. Report any compromised packages found

## How It Works

The `scan.js` file is a self-contained script that:

1. **Fetches Compromised Package Data**:
   - Connects to multiple security advisory sources
   - Parses HTML content to extract package names and compromised versions
   - Handles different advisory formats with specialized parsers
   - Builds a unified database of compromised packages

2. **Scans Local Project Files**:
   - Analyzes package.json for direct dependencies
   - Checks all dependency types (dependencies, devDependencies, etc.)
   - Recursively examines package-lock.json for nested dependencies
   - Implements proper semver range matching to detect version ranges that include compromised versions

3. **Reports Findings**:
   - Displays clear output with emoji indicators
   - Shows detailed information about each detected compromised package
   - Provides a summary of the advisory database

## Example Output

When no compromised packages are found:

```
Fetching compromised packages...
Fetching from https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/...
Found 200 packages from https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/
...
Advisory sources: 4 succeeded, 0 failed
Total unique packages found: 202
Scanning package.json...
Scanning package-lock.json...

✅ No compromised packages detected in your project.

Advisory database summary:
- Total compromised packages: 202
- Examples of compromised packages:
  * @ctrl/tinycolor (3 versions)
  * angulartics2 (3 versions)
  * @ctrl/deluge (3 versions)
  ...
```

When compromised packages are detected:

```
Fetching compromised packages...
...
Advisory sources: 4 succeeded, 0 failed
Total unique packages found: 202
Scanning package.json...
Scanning package-lock.json...

🚨 Detected compromised packages:
- @ctrl/tinycolor@4.1.1 (dependencies)
- angulartics2@14.1.1 (devDependencies)

Advisory database summary:
...
```

When version ranges match compromised versions:

```
🚨 Detected compromised packages:
- @ctrl/tinycolor@~4.1.0 (matches 4.1.1) (dependencies)
- angulartics2@>=14.0.0 <15.0.0 (matches 14.1.2) (devDependencies)
```

## Technical Details

The scanner implements:

- **Custom HTML Parsers**: For different advisory formats (Wiz, StepSecurity, etc.)
- **Semver Range Resolution**: Properly handles `~`, `^`, `.x`, and complex ranges
- **Parallel Network Requests**: For faster data collection
- **Error Handling**: Gracefully handles network failures
- **Recursive Dependency Analysis**: For nested dependencies in package-lock.json

## Security Notes

- The scanner only reads your package.json and package-lock.json files
- It makes outbound HTTPS requests to security advisory websites
- No data from your project is sent to any external service
- All processing happens locally on your machine

## Limitations

- Advisory sources may change their URL structure or HTML format
- The scanner relies on public security advisories being available and up-to-date
- It cannot detect compromised packages that haven't been identified in the advisories

## Testing

A test suite is included in the repository to verify the scanner's functionality against various package configurations:

```bash
node test.js
```

## License

MIT

## Credits

This tool was created to help developers quickly check their projects for compromised packages from the Shai-Hulud attack. Inspired by the Python-based [shai-hulud-audit-toolkit](https://github.com/adpablos/shai-hulud-audit-toolkit).
