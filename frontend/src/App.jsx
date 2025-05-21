// File: frontend/src/App.jsx
import React from "react";
import { BrowserRouter as Router, Route, Routes, NavLink } from "react-router-dom";
import CertificateConverter from "./components/CertificateConverter.jsx";
import CSRGenerator from "./components/CSRGenerator.jsx";
import SSLChecker from "./components/SSLChecker.jsx";
import CSRDecoder from "./components/CSRDecoder.jsx";
import SSLDecoder from "./components/SSLDecoder.jsx";

const App = () => {
  return (
    <div className="bg-gray-900 min-h-screen text-white">
      <Router>
        <nav className="bg-gray-800 p-4 flex space-x-4">
          <NavLink to="/convert" className="hover:underline">Convert</NavLink>
          <NavLink to="/csr-generator" className="hover:underline">CSR Generator</NavLink>
          <NavLink to="/ssl-check" className="hover:underline">SSL Check</NavLink>
          <NavLink to="/csr-decode" className="hover:underline">CSR Decode</NavLink>
          <NavLink to="/ssl-decode" className="hover:underline">SSL Decode</NavLink>
        </nav>
        <div className="p-6">
          <Routes>
            <Route path="/convert" element={<CertificateConverter />} />
            <Route path="/csr-generator" element={<CSRGenerator />} />
            <Route path="/ssl-check" element={<SSLChecker />} />
            <Route path="/csr-decode" element={<CSRDecoder />} />
            <Route path="/ssl-decode" element={<SSLDecoder />} />
            <Route path="*" element={<div>Welcome to SSL Toolkit</div>} />
          </Routes>
        </div>
      </Router>
    </div>
  );
};

export default App;
