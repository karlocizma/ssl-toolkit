import React, { createContext, useContext, useEffect, useState } from 'react';
import { featuresAPI } from '../services/api';

const OFF = { acme: false };

export const FeaturesContext = createContext(OFF);

// Optional server features. Everything counts as off until the server says otherwise, so a link never
// appears and then 404s, and a failed request leaves the rest of the app working.
export function FeaturesProvider({ children }) {
  const [features, setFeatures] = useState(OFF);

  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(() => featuresAPI.get())
      .then((res) => { if (active) setFeatures({ acme: Boolean(res.data && res.data.acme) }); })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  return <FeaturesContext.Provider value={features}>{children}</FeaturesContext.Provider>;
}

export const useFeatures = () => useContext(FeaturesContext);
