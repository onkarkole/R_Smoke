package com.qa.stepdefinitions;

import com.qa.pages.LoginPage;
import com.qa.utils.EmailManager;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.testng.Assert;

public class LoginTest {

    private static final LoginPage loginPage= new LoginPage();

    @Given("User is on the login page")
    public void user_is_on_the_login_page(){
        loginPage.navigateToApplication();
    }

    @When("User enter the username")
    public void user_enter_the_username(){
        loginPage.enterUsername();
    }

    @Then("Enter OTP")
    public void enter_otp() {
        loginPage.enterOTP();
    }

    @Then("Click on submit button")
    public void click_on_submit_button(){
        loginPage.clickSubmitButton();
    }

    @Then("Click on login button")
    public void click_on_login_button(){
        loginPage.clickLoginButton();
    }

    @Then("Verify if dashboard is visible")
    public void verify_if_dashboard_is_visible(){
        try{
            Assert.assertTrue(loginPage.validateSmokeTest());
            EmailManager.deleteOtpEmails();
        }catch(Exception e){
            EmailManager.deleteOtpEmails();
        }

    }

    @Then("Clicked on logout button")
    public void Clicked_on_logout_button(){
        loginPage.clickOnLogout();
    }


}
