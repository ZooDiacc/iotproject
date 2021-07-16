const express = require('express');
const router = express.Router();
const validUrl = require('valid-url');
const shortid = require('shortid');
const config = require('config');
const Url = require('../models/Url');
const jwt = require('jsonwebtoken');





// @route     POST /api/url/shorten
// @desc      Create short URL
router.post('/shorten', async(req, res) => {
    const { longUrl, token } = req.body;

    if (!token) {
        res.status(401).json({
            message: "Unauthorized"
        })
    }

    const verify = await jwt.verify(token, "ELYAS");

    // console.log("VERIFY", verify.email)


    const baseUrl = config.get('baseUrl');


    // Check base url
    if (!validUrl.isUri(baseUrl)) {
        return res.status(401).json('Invalid base url');
    }

    // Create url code
    const urlCode = shortid.generate();

    // Check long url
    if (validUrl.isUri(longUrl)) {
        try {

            const shortUrl = baseUrl + urlCode;

            url = new Url({
                longUrl,
                shortUrl,
                urlCode,
                email: verify.email,
                date: new Date()
            });

            await url.save();

            res.json(url);
            // }
        } catch (err) {
            console.error(err);
            res.status(500).json('Server error');
        }
    } else {
        res.status(401).json('Invalid long url');
    }
});

router.get('/', function(req, res, next) {

});
module.exports = router;