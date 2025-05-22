/* Component: CertificateConverter.jsx */
// File: frontend/src/components/CertificateConverter.jsx
import React, { useState } from "react";

const SSLConverter = () => {
  const [file, setFile] = useState(null);
  const [targetFormat, setTargetFormat] = useState("pem");
  const [converted, setConverted] = useState(null);
  const [filename, setFilename] = useState("");
  const [password, setPassword] = useState("");

  const handleConvert = async () => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("target_format", targetFormat);
    if (targetFormat === "pfx") {
      formData.append("password", password);
    }

    const res = await fetch("/api/convert-ssl", {
      method: "POST",
      body: formData,
    });

    if (res.ok) {
      const blob = await res.blob();
      const downloadUrl = URL.createObjectURL(blob);
      setConverted(downloadUrl);
      setFilename(`converted_cert.${targetFormat}`);
    } else {
      alert("Conversion failed.");
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl mb-2">SSL Converter</h2>

      <div className="space-y-2">
        <input
          type="file"
          className="block text-white"
          onChange={(e) => setFile(e.target.files[0])}
        />

        <div className="flex gap-4 items-center">
          <label className="text-white">Output Format:</label>
          <select
            className="p-2 bg-gray-800 text-white rounded"
            value={targetFormat}
            onChange={(e) => setTargetFormat(e.target.value)}
          >
            <option value="pem">PEM</option>
            <option value="pfx">PFX</option>
          </select>
        </div>

        {targetFormat === "pfx" && (
          <input
            type="password"
            placeholder="Enter password for PFX (optional)"
            className="w-full p-2 bg-gray-800 text-white rounded"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        )}
      </div>

      <button className="bg-blue-600 px-4 py-2 rounded" onClick={handleConvert}>
        Convert
      </button>

      {converted && (
        <div className="mt-4">
          <a
            href={converted}
            download={filename}
            className="text-blue-400 underline"
          >
            Download Converted Certificate
          </a>
        </div>
      )}
    </div>
  );
};

export default SSLConverter;

