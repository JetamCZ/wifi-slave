const fetch = require('node-fetch');
const fs = require('fs')
const CronJob = require('cron').CronJob;
const uncaught = require('uncaught');
const { exec } = require("child_process");

uncaught.start();
uncaught.addListener(function (error) {
    console.error('Uncaught error or rejection: ', error.message);
});

const cronJ = new CronJob('0 */10 * * * *', async () => {
    fs.readFile('commit.txt', 'utf8', function(err, data) {
        const code = data
        
        fetch('https://api.github.com/repos/JetamCZ/wifi-slave/commits/master')
        .then(response => response.json())
        .then(data => {
            if(data.sha !== code) {
                exec('sudo pkill python3')
                exec('git ../ pull')

                fs.writeFile('commit.txt', data.sha, function (err) {
                    if (err) throw err;
                });

                exec('sudo reboot now')
            }
        });

    });

}, null, true, 'Europe/Prague')

cronJ.start()