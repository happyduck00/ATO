# Step-by-Step Setup Instructions

## Prerequisites Check

Before starting, make sure you have:
- [ ] Docker installed and running
- [ ] Git installed
- [ ] GitHub account created

## Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `ATO`
3. Description: "Account Takeover Security Testing Guide"
4. Public or Private (your choice)
5. **Do NOT** initialize with README, .gitignore, or license (we'll add these)
6. Click "Create repository"

## Step 2: Create Project Structure Locally

Open your terminal and run:

```bash
# Create project directory
mkdir ATO
cd ATO

# Initialize git
git init
git branch -M main
```

## Step 3: Create All Project Files

You'll need to create these files in your ATO directory. I'll provide the content for each:

### File 1: Create `package.json`
```bash
# Copy the content from the "package.json" artifact I created
# Save it as package.json in the ATO directory
```

### File 2: Create `Dockerfile`
```bash
# Copy the content from the "Dockerfile" artifact
# Save it as Dockerfile (no extension) in the ATO directory
```

### File 3: Create `docker-compose.yml`
```bash
# Copy the content from the "docker-compose.yml" artifact
# Save it in the ATO directory
```

### File 4: Create `nginx.conf`
```bash
# Copy the content from the "nginx.conf" artifact
# Save it in the ATO directory
```

### File 5: Create `.gitignore`
```bash
# Copy the content from the ".gitignore" artifact
# Save it as .gitignore in the ATO directory
```

### File 6: Create `README.md`
```bash
# Copy the content from the "README.md" artifact
# Update YOUR_USERNAME with your actual GitHub username
# Save it in the ATO directory
```

### File 7: Create `public/index.html`
```bash
# Create public directory
mkdir public

# Copy the content from "public/index.html" artifact
# Save it as public/index.html
```

### File 8: Create `src/index.js`
```bash
# Create src directory
mkdir src

# Copy the content from "src/index.js" artifact
# Save it as src/index.js
```

### File 9: Create `src/index.css`
```bash
# Copy the content from "src/index.css" artifact
# Save it as src/index.css
```

### File 10: Create `src/App.js`
```bash
# This is the BIG file - it contains both the ATO map and OAuth deep dive
# I need to provide this separately because it's large
# You'll copy the entire content from the original artifacts we created
```

## Step 4: Create src/App.js (The Main Component)

Create `src/App.js` with this structure:

```javascript
import React, { useState } from 'react';

// Import both components we created earlier
// You'll need to paste the ENTIRE content of:
// 1. The ATO Mind Map component (ato-mindmap artifact)
// 2. The OAuth Deep Dive component (oauth-deepdive artifact)

function App() {
  const [activeView, setActiveView] = useState('ato');

  return (
    <div>
      <nav className="bg-gray-900 text-white p-4">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveView('ato')}
            className={\`px-4 py-2 rounded \${activeView === 'ato' ? 'bg-blue-600' : 'bg-gray-700'}\`}
          >
            ATO Reference Map
          </button>
          <button
            onClick={() => setActiveView('oauth')}
            className={\`px-4 py-2 rounded \${activeView === 'oauth' ? 'bg-blue-600' : 'bg-gray-700'}\`}
          >
            OAuth 2.0 Deep Dive
          </button>
        </div>
      </nav>
      
      {activeView === 'ato' ? <ATOMindMap /> : <OAuthDeepDive />}
    </div>
  );
}

export default App;
```

**IMPORTANT**: You'll need to:
1. Copy the ENTIRE component code from the `ato-mindmap` artifact
2. Copy the ENTIRE component code from the `oauth-deepdive` artifact
3. Paste them both into App.js
4. The file will be large (~2000+ lines) - that's normal

## Step 5: Push to GitHub

```bash
# Add all files
git add .

# Commit
git commit -m "Initial commit: ATO Security Testing Guide"

# Add your GitHub remote (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/ATO.git

# Push to GitHub
git push -u origin main
```

## Step 6: Test Locally with Docker

```bash
# Build and run
docker-compose up --build

# Wait for build to complete (first time takes 2-3 minutes)
# You should see: "Compiled successfully!"

# Open browser to http://localhost:3000
```

## Step 7: Verify Everything Works

- [ ] Page loads without errors
- [ ] You can see both "ATO Reference Map" and "OAuth 2.0 Deep Dive" buttons
- [ ] Clicking buttons switches between the two views
- [ ] You can expand categories and see details
- [ ] Checkboxes work on testing steps

## Troubleshooting

### Docker build fails
```bash
# Clean everything and retry
docker-compose down
docker system prune -a
docker-compose up --build
```

### Port 3000 already in use
```bash
# Edit docker-compose.yml, change:
ports:
  - "3001:80"  # Use port 3001 instead
```

### Can't find lucide-react
```bash
# Install dependencies first
npm install
# Then rebuild Docker
docker-compose up --build
```

## What You Should Have Now

```
ATO/
├── public/
│   └── index.html
├── src/
│   ├── App.js
│   ├── index.js
│   └── index.css
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── package.json
└── README.md
```

## Next Steps

1. Share the GitHub link with teammates
2. They can clone and run with one command: `docker-compose up`
3. Start using it for security testing!
4. Customize and add your own findings

## Need Help?

- Check Docker logs: `docker-compose logs`
- Restart container: `docker-compose restart`
- Rebuild from scratch: `docker-compose down && docker-compose up --build`
