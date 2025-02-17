const puppeteer = require('puppeteer');
const assert = require('assert');
const path = require('path');
const cas = require('../../cas.js');

async function unsolicited(page, target) {
    const entityId = "http://localhost:9443/simplesaml/module.php/saml/sp/metadata.php/default-sp";

    let url = "https://localhost:8443/cas/idp/profile/SAML2/Unsolicited/SSO";
    url += `?providerId=${entityId}`;
    url += `&target=${target}`;

    await cas.goto(page, url);
    await page.waitForTimeout(8000);
    const result = await page.url();
    await cas.log(`Page url: ${result}`);
    assert(result.includes(target));
}

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);
    const response = await cas.goto(page, "https://localhost:8443/cas/idp/metadata");
    await cas.log(`${response.status()} ${response.statusText()}`);
    assert(response.ok());

    await cas.gotoLogin(page);
    await page.waitForTimeout(2000);

    await cas.loginWith(page);
    await page.waitForTimeout(5000);
    
    await unsolicited(page, "https://apereo.github.io");
    await page.waitForTimeout(5000);

    await unsolicited(page, "https://github.com/apereo/cas");
    await page.waitForTimeout(4000);

    await cas.removeDirectoryOrFile(path.join(__dirname, '/saml-md'));
    await browser.close();
})();
