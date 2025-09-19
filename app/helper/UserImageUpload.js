
const multer = require("multer");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    return cb(null, 'uploads');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = (`${Date.now()}-${file.originalname}`);
    return cb(null, uniqueSuffix);
  }
})

const UserImageUpload = multer({ storage });

module.exports = UserImageUpload;