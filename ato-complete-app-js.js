// NOTE: This is a simplified template. 
// You need to copy the FULL component code from both artifacts:
// 1. ato-mindmap artifact (the testing reference map)
// 2. oauth-deepdive artifact (the OAuth security guide)
// 
// Both are React components that should be pasted into this file.

import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, Unlock, Key, Users, AlertTriangle, Lock, FileText, TestTube, BookOpen, Code, Bug, Terminal, CheckCircle, XCircle, Book } from 'lucide-react';

// ============================================================================
// COMPONENT 1: ATO MIND MAP
// Copy the ENTIRE MindMap component from the ato-mindmap artifact here
// It should start with: const MindMap = () => {
// And end with: export default MindMap;
// Remove the "export default" line at the end
// ============================================================================

const ATOMindMap = () => {
  // PASTE THE FULL COMPONENT CODE FROM ato-mindmap HERE
  // This includes all the data, Node component, DetailPanel, everything
  // The artifact has the complete working code
  
  return <div>ATO Mind Map Component - Replace this with actual code</div>;
};

// ============================================================================
// COMPONENT 2: OAUTH DEEP DIVE  
// Copy the ENTIRE OAuthDeepDive component from the oauth-deepdive artifact here
// It should start with: const OAuthDeepDive = () => {
// And end with: export default OAuthDeepDive;
// Remove the "export default" line at the end
// ============================================================================

const OAuthDeepDive = () => {
  // PASTE THE FULL COMPONENT CODE FROM oauth-deepdive HERE
  // This includes all the OAuth data, Section component, DetailView, everything
  // The artifact has the complete working code
  
  return <div>OAuth Deep Dive Component - Replace this with actual code</div>;
};

// ============================================================================
// MAIN APP COMPONENT - Navigation between the two views
// ============================================================================

function App() {
  const [activeView, setActiveView] = useState('ato');

  return (
    <div className="h-screen flex flex-col">
      {/* Navigation Bar */}
      <nav className="bg-gray-900 text-white p-4 shadow-lg">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <h1 className="text-2xl font-bold">ATO Security Testing Guide</h1>
          <div className="flex gap-4">
            <button
              onClick={() => setActiveView('ato')}
              className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                activeView === 'ato' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              📚 ATO Reference Map
            </button>
            <button
              onClick={() => setActiveView('oauth')}
              className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                activeView === 'oauth' 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              🔐 OAuth 2.0 Deep Dive
            </button>
          </div>
        </div>
      </nav>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden">
        {activeView === 'ato' ? <ATOMindMap /> : <OAuthDeepDive />}
      </div>
    </div>
  );
}

export default App;
