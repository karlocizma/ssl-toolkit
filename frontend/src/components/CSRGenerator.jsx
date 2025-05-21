import React, { useState } from "react";

const CSRGenerator = () => {
  const [form, setForm] = useState({
    country: "",
    state: "",
    locality: "",
    organization: "",
    organizational_unit: "",
    common_name: "",
    email: "",
  });

  const [result, setResult] = useState(null);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleGenerate = async () => {
    const res = await fetch("/api/csr-generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });

    const data = await res.json();
    setResult(data);
  };

  return (
    <div>
      <h2 className="text-xl mb-2">Generate CSR</h2>
      {["country", "state", "locality", "organization", "organizational_unit", "common_name", "email"].map((field) => (
        <input
          key={field}
          className="w-full mb-2 p-2 bg-gray-800 text-white"
          name={field}
          placeholder={field.replace(/_/g, " ").toUpperCase()}
          value={form[field]}
          onChange={handleChange}
        />
      ))}
      <button className="bg-blue-600 px-4 py-2 rounded" onClick={handleGenerate}>
        Generate
      </button>

      {result && (
        <div className="mt-4">
          <h3 className="text-lg mb-1">Private Key:</h3>
          <textarea className="w-full h-40 p-2 bg-gray-900 text-green-400 mb-4" readOnly value={result.private_key} />
          <h3 className="text-lg mb-1">CSR:</h3>
          <textarea className="w-full h-40 p-2 bg-gray-900 text-green-400" readOnly value={result.csr} />
        </div>
      )}
    </div>
  );
};

export default CSRGenerator;

