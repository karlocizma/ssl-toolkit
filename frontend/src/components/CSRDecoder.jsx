/* Component: CSRDecoder.jsx */
// File: frontend/src/components/CSRDecoder.jsx
import React, { useState } from "react";

const CSRDecoder = () => {
  const [csr, setCsr] = useState("");
  const [result, setResult] = useState(null);

  const handleDecode = async () => {
    const res = await fetch("/api/csr-decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csr })
    });
    const data = await res.json();
    setResult(data);
  };

  return (
    <div>
      <h2 className="text-xl mb-2">CSR Decoder</h2>
      <textarea
        className="w-full p-2 bg-gray-800 text-white mb-2"
        rows="6"
        placeholder="Paste CSR here..."
        value={csr}
        onChange={(e) => setCsr(e.target.value)}
      />
      <button className="bg-blue-600 px-4 py-2 rounded" onClick={handleDecode}>Decode</button>

      {result && (
        <div className="mt-4 bg-gray-800 p-4 rounded">
          {Object.entries(result).map(([key, value]) => (
            <p key={key}><strong>{key}:</strong> {value}</p>
          ))}
        </div>
      )}
    </div>
  );
};

export default CSRDecoder;
