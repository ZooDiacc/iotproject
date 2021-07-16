const express = require('express');
const router = express.Router();
const Url = require('../models/Url');
const cors = require('cors');

router.get("/", (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*")
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Max-Age", "1800");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, PATCH, OPTIONS");
});

// @route     GET /:code
// @desc      Redirect to long/original URL
router.get('/:code', async(req, res) => {
    try {
        const url = await Url.findOne({ urlCode: req.params.code });
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        console.log('ip', ip)

        if (url) {
            return res.redirect(url.longUrl);
        } else {
            return res.status(404).json('No url found');
        }
    } catch (err) {
        console.error(err);
        res.status(500).json('Server error');
    }
});

module.exports = router;