# Contributing to Plex Command Center

First off, thank you for considering contributing! This project is actively developed and we welcome contributions.

## 🐛 Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (OS, Docker version, Plex/Tautulli/Jellyseerr versions)
- **Logs** if applicable (`docker logs plex-command-center`)

## 💡 Suggesting Features

Feature requests are welcome! Please:

- **Check existing requests** first
- **Describe the use case** - why would this be useful?
- **Explain the expected behavior**
- **Consider implementation complexity**

## 🔧 Development Workflow

### Setting Up Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/plex-command-center.git
cd plex-command-center

# Install dependencies
npm install

# Create docker-compose.yml from example
cp docker-compose.yml.example docker-compose.yml
nano docker-compose.yml  # Add your API keys

# Run in development mode
node backend-server.js

# Or run in Docker
docker-compose build
docker-compose up
```

### Code Style

- Use 2 spaces for indentation
- Add comments for complex logic
- Keep functions focused and single-purpose
- Use meaningful variable names
- Follow existing code patterns

### Making Changes

1. **Fork the repository**
2. **Create a feature branch** from `main`
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Make your changes**
4. **Test thoroughly** - ensure nothing breaks
5. **Commit with clear messages**
   ```bash
   git commit -m "Add: User preference persistence for widget layout"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/my-new-feature
   ```
7. **Open a Pull Request**

### Commit Message Format

```
Type: Short description

Longer description if needed, explaining what and why.

- Change 1
- Change 2
```

**Types:**
- `Add:` New features
- `Fix:` Bug fixes
- `Update:` Changes to existing features
- `Remove:` Removed features
- `Docs:` Documentation changes
- `Refactor:` Code refactoring
- `Test:` Adding tests

### Pull Request Guidelines

- Keep PRs focused on a single feature/fix
- Update README.md if adding new features
- Update CHANGELOG.md
- Test with actual Plex/Tautulli/Jellyseerr instances
- Ensure Docker build succeeds
- Include screenshots for UI changes

## 🧪 Testing

Before submitting:

```bash
# Build Docker image
docker-compose build

# Start services
docker-compose up -d

# Check logs for errors
docker-compose logs -f

# Access dashboard
# http://localhost:3001

# Test all major features:
# - Dashboard loads
# - Widgets display data
# - Active streams show correctly
# - Jellyseerr search works
# - Collections can be created
# - Filters work in history
```

## 📁 Project Structure

```
plex-command-center/
├── backend-server.js       # Main Express server
│   ├── Plex API endpoints
│   ├── Tautulli integration
│   ├── Jellyseerr integration
│   ├── Zabbix integration
│   └── System metrics
│
├── public/
│   └── index.html          # React frontend (single file)
│       ├── Dashboard widgets
│       ├── Tab components
│       └── Modal dialogs
│
├── package.json            # Dependencies
├── Dockerfile              # Container build
└── docker-compose.yml      # Service orchestration
```

## 🎯 Areas Needing Help

We especially welcome contributions in these areas:

- **Mobile Responsiveness** - Better mobile/tablet layouts
- **Testing** - Automated tests for API endpoints
- **Documentation** - Screenshots, video guides, translations
- **Features** - See roadmap in README.md
- **Bug Fixes** - Check open issues
- **Performance** - Optimize API calls, reduce refresh intervals

## 📋 Coding Best Practices

### Backend (backend-server.js)

```javascript
// Good: Clear endpoint with error handling
app.get('/api/plex/status', async (req, res) => {
  try {
    const response = await axios.get(`${config.plex.url}/`);
    res.json({ online: true, data: response.data });
  } catch (error) {
    console.error('Plex status error:', error.message);
    res.json({ online: false, error: error.message });
  }
});

// Good: Consistent error logging
console.error('Descriptive error message:', error.message);

// Good: Timeout on external API calls
axios.get(url, { timeout: 5000 })
```

### Frontend (public/index.html)

```javascript
// Good: Error handling in data fetching
const fetchData = async () => {
  try {
    const res = await fetch('/api/endpoint');
    const data = await res.json();
    setData(data);
  } catch (error) {
    console.error('Fetch error:', error);
    showToast('Failed to load data', 'error');
  }
};

// Good: Conditional rendering
{data ? (
  <div>{data.value}</div>
) : (
  <div>Loading...</div>
)}

// Good: Safe data access
{user?.name || 'Unknown'}
```

## 🚀 Release Process

Maintainers will:

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Create Git tag `v2.5.2`
4. Build and push Docker image
5. Create GitHub release

## 📞 Getting Help

- **Questions?** Open a Discussion
- **Stuck?** Comment on your PR
- **Need clarification?** Ask in the issue

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Plex Command Center!** 🎉
