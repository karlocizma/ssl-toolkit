/* Component: SSLChecker.jsx */
// File: frontend/src/components/SSLChecker.jsx
import React, { useState } from "react";

const SSLChecker = () => {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState(null);

  const handleCheck = async () => {
    const res = await fetch("/api/ssl-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    setResult(data);
  };

  return (
    <div>
      <h2 className="text-xl mb-2">SSL Checker</h2>
      <input
        type="text"
        className="w-full p-2 bg-gray-800 text-white mb-2"
        placeholder="example.com"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
      />
      <button className="bg-blue-600 px-4 py-2 rounded" onClick={handleCheck}>Check SSL</button>

      {result && (
        <div className="mt-4 bg-gray-800 p-4 rounded text-white">
           <p><strong>Issuer:</strong> {result.issuer}</p>
           <p><strong>Valid From:</strong> {result.valid_from}</p>
           <p><strong>Valid To:</strong> {result.valid_to}</p>
           <p>
	     <strong>Expired:</strong>{" "}
             <span className={result.expired ? "text-red-500" : "text-green-400"}>
               {result.expired ? "Yes" : "No"}
             </span>
           </p>
        </div>
      )}
    </div>
  );
};

export default SSLChecker;
