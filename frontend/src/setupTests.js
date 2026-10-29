import '@testing-library/jest-dom';
import { TextDecoder, TextEncoder } from 'util';

// CRA's Jest 27 / jsdom has no TextEncoder, which react-router 7 needs when it loads.
if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
  global.TextDecoder = TextDecoder;
}
