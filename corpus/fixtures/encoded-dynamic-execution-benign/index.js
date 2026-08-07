// Decoding alone is not dynamic execution.
const payload = atob('Y29uc29sZS5sb2coJ2hlbGxvJyk=');
const docs = "eval(atob('not code'))";
