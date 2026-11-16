# Publishing Aries v0.5.0

## Repository

Create an empty GitHub repository, then from this extracted source folder run:

```powershell
git init
git add .
git commit -m "Release Aries v0.5.0 Windows developer preview"
git branch -M main
git remote add origin https://github.com/YOUR-ACCOUNT/aries.git
git push -u origin main
```

## Release

```powershell
git tag -a v0.5.0 -m "Aries v0.5.0 Windows developer preview"
git push origin v0.5.0
```

Create a GitHub Release from the tag. Attach the distribution ZIP and its SHA256 file. Mark the release as a pre-release because authentication, remote deployment, Linux support, and external validation are not complete.

## Repository settings

- Enable private vulnerability reporting and Dependabot alerts.
- Protect `main` and require the test workflow before merging.
- Disable GitHub Issues until security/contact instructions and templates match your support capacity, or clearly label the project best-effort.
- Never upload real evidence or case diagnostics containing victim data.
