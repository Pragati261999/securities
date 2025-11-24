// module.exports = function (...allowedRoles) {
//     return (req, res, next) => {

//         if (!req.user || !req.user.role) {
//             return res.status(403).json({ message: "Unauthorized" });
//         }

//         if (!allowedRoles.includes(req.user.role)) {
//             return res.status(403).json({ message: "Access denied: insufficient permissions" });
//         }

//         next();
//     };
// };
module.exports = function (...allowedRoles) {
    return (req, res, next) => {

        if (!req.user || !req.user.role) {
            return res.status(403).json({ message: "Unauthorized" });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: "Access denied: insufficient permissions" });
        }

        next();
    };
};

