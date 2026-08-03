const http = require('http');

// Test the metrics endpoint
const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/metrics',
    method: 'GET'
};

const req = http.request(options, (res) => {
    console.log(`Status Code: ${res.statusCode}`);
    console.log(`Headers:`, res.headers);
    
    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });
    
    res.on('end', () => {
        if (res.statusCode === 200) {
            console.log('\n✅ Metrics page loaded successfully');
            console.log(`Response length: ${data.length} bytes`);
            // Check for common errors in HTML
            if (data.includes('Error:')) {
                console.log('⚠️  Found error message in response');
                const errorMatch = data.match(/Error:([^<]+)/);
                if (errorMatch) {
                    console.log('Error:', errorMatch[1]);
                }
            }
        } else {
            console.log('\n❌ Metrics page failed');
            console.log('Response:', data.substring(0, 500));
        }
    });
});

req.on('error', (error) => {
    console.error('❌ Request error:', error.message);
    console.log('Make sure the server is running on port 3000');
});

req.end();









