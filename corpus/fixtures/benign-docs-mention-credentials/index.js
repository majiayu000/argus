// Formats a publish checklist. No filesystem or network access.
module.exports = function checklist(steps) {
  return steps.map((step, index) => `${index + 1}. ${step}`).join("\n");
};
