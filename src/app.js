import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, Unlock, Key, Users, AlertTriangle, Lock, FileText, TestTube, BookOpen, Code, Bug, Terminal, CheckCircle, XCircle, Book } from 'lucide-react';

// Component 1: ATO Mind Map
const ATOMindMap = () => {
  const [expanded, setExpanded] = useState({});
  const [selected, setSelected] = useState(null);
  
  // ... ALL the MindMap component code from ato-mindmap.tsx
  // (everything inside the MindMap component)
  
  return (
    <div className="h-screen flex flex-col bg-gray-50">
      {/* ... the JSX return from MindMap */}
    </div>
  );
};

// Component 2: OAuth Deep Dive
const OAuthDeepDive = () => {
  const [expanded, setExpanded] = useState({ '0': true });
  const [selected, setSelected] = useState(null);
  
  // ... ALL the OAuthDeepDive component code
  
  return (
    <div className="h-screen flex flex-col bg-gray-100">
      {/* ... the JSX return from OAuthDeepDive */}
    </div>
  );
};

// Main App Component
function App() {
  const [activeView, setActiveView] = useState('ato');

  return (
    <div className="h-screen flex flex-col">
      <nav className="bg-gray-900 text-white p-4 shadow-lg">
        {/* ... navigation */}
      </nav>
      <div className="flex-1 overflow-hidden">
        {activeView === 'ato' ? <ATOMindMap /> : <OAuthDeepDive />}
      </div>
    </div>
  );
}

export default App;
