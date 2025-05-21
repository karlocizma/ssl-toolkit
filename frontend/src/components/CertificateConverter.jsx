/* Component: CertificateConverter.jsx */
// File: frontend/src/components/CertificateConverter.jsx
import React, { useState } from "react";

const CertificateConverter = () => {
  const [input, setInput] = useState("");
  const [format, setFormat] = useState("pem");
  const [output, setOutput] = useState("");

  const handleConvert = async () => {
    const res = await fetch("/api/convert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, format })
    });
    const data = await res.json();
    setOutput(data.output);
  };

  return (
    <div>
      <h2 className="text-xl mb-2">Certificate Converter</h2>
      <textarea className="w-full p-2 bg-gray-800 text-white" rows="8" value={input} onChange={(e) => setInput(e.target.value)} placeholder="Paste certificate here..." />
      <select className="bg-gray-700 text-white mt-2 p-2" value={format} onChange={(e) => setFormat(e.target.value)}>
        <option value="pem">PEM</option>
        <option value="der">DER</option>
        <option value="pfx">PFX</option>
      </select>
      <button className="block mt-4 bg-blue-600 px-4 py-2 rounded" onClick={handleConvert}>Convert</button>
      {output && (
        <textarea className="w-full mt-4 p-2 bg-gray-800 text-white" rows="8" readOnly value={output} />
      )}
    </div>
  );
};

export default CertificateConverter;

/* Other components (CSRGenerator, SSLChecker, CSRDecoder, SSLDecoder) will follow next */
