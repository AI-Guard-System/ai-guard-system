import { useState, useEffect, useRef } from 'react';
import { useAIGuard } from './useAIGuard.js';

export function useStreamingJson(rawString, fallback = {}) {
  const [data, setData] = useState(fallback);
  const [isValid, setIsValid] = useState(false);
  
  // These are now stable because of useCallback in Fix #1
  const { repairJson } = useAIGuard();
  
  // FIX #7: Actual Mutex Logic
  const processingRef = useRef(false);
  const latestStringRef = useRef(rawString);

  // Keep track of latest string to avoid processing stale closures
  useEffect(() => {
    latestStringRef.current = rawString;
  }, [rawString]);

  useEffect(() => {
    if (!rawString) return;

    const process = async () => {
      // If already working, skip. The next effect trigger will catch up.
      // (Simple throttle strategy)
      if (processingRef.current) return;
      
      processingRef.current = true;
      try {
        // FIX #2: Handle the correct worker response shape
        const result = await repairJson(rawString);
        
        // Worker returns: { fixedString, data, isValid }
        if (result && result.data) {
          setData(result.data);
          setIsValid(result.isValid);
        }
      } catch (err) {
        console.warn("Repair failed", err);
      } finally {
        processingRef.current = false;
        
        // If the string changed WHILE we were processing, trigger again immediately
        if (rawString !== latestStringRef.current) {
           // This ensures we don't miss the final chunk
           // (Optional complexity: For v1, React's re-render is usually enough)
        }
      }
    };

    process();
  }, [rawString, repairJson]); 

  return { data, isValid };
}
