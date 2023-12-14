exports.originalOrigin = function(req) {
  return req.origin || req.get('origin');
};
