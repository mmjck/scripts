const axios = require('axios');

const params = {
    username: "useradmin",
    psd: "asdas"
  }

axios.post('http://192.168.1.1/boaform/admin/formLogin', params).then(resp => {
  
    console.log(resp);
});
