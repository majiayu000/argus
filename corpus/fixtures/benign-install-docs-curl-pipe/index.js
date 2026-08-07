// Reports which documented tools resolve on PATH. Spawns nothing.
module.exports = function detect(names, lookup) {
  return names.filter((name) => Boolean(lookup(name)));
};
