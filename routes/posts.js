const router = require('express').Router();
const verify = require('./verifyToken');

router.get('/', verify, async (req, res) => {
	res.json({posts: [{title: 'My Posts', desc: 'Just dummy data'}]});
});

module.exports = router;
