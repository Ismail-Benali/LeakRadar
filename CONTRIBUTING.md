# Contributing to LeakRadar

First off, thank you for taking the time to contribute! ❤️

All contributions, bug reports, bug fixes, documentation improvements, enhancements, and ideas are welcome.

## How to Contribute

### 1. Fork & Clone
Fork the repository and clone your fork locally:
```bash
git clone https://github.com/YOUR_USERNAME/LeakRadar.git
cd LeakRadar
```

### 2. Set Up Environment
Create a virtual environment and install development dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
```

### 3. Run Tests
Ensure all existing tests pass successfully:
```bash
pytest tests/
```

### 4. Create a Branch
Create a descriptive branch for your feature or bug fix:
```bash
git checkout -b feature/amazing-feature
```

### 5. Commit & Push
Commit your changes with clear commit messages and push to your fork:
```bash
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

### 6. Open a Pull Request
Open a Pull Request on GitHub against the `main` branch, explaining your changes clearly.
