import { AuthenticatedTemplate, UnauthenticatedTemplate, useMsal } from "@azure/msal-react";

import { Nav, Navbar, Button, Dropdown, DropdownButton} from "react-bootstrap";

import { loginRequest } from "../authConfig";
import { Redirect } from "react-router-dom";

export const NavigationBar = () => {

    const { instance } = useMsal();

    /**
     * Most applications will need to conditionally render certain components based on whether a user is signed in or not. 
     * msal-react provides 2 easy ways to do this. AuthenticatedTemplate and UnauthenticatedTemplate components will 
     * only render their children if a user is authenticated or unauthenticated, respectively.
     */
     const handelLogin =  () => {
        instance.loginPopup(loginRequest)
        .catch(error => {
            console.error(error);
        });
    }

    const handleLogout = () => {
        localStorage.removeItem('currentClaim');
        instance.logoutPopup({ 
            postLogoutRedirectUri: "/",
            mainWindowRedirectUri: "/" 
        })
    }

    return (
        <>
            <Navbar bg="primary" variant="dark">
                <a className="navbar-brand" href="/">Microsoft identity platform</a>
                <AuthenticatedTemplate>
                    <Nav.Link as={Button} href="/todolist">TodoList</Nav.Link>
                    <Button  variant="warning" className="ml-auto"  drop="left" as="button" onClick={handleLogout}> Sign out </Button> 
                </AuthenticatedTemplate>
                <UnauthenticatedTemplate>
                    <Button variant="secondary"  className="ml-auto" drop="left" as="button" onClick={handelLogin}>Sign in</Button>
                </UnauthenticatedTemplate>
            </Navbar>
        </>
    );
};