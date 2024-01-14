package app.key.springkeycloak.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * @author MJ Makki
 * @version 1.0
 * @license SkyLimits, LLC (<a href="https://www.skylimits.tech">SkyLimits, LLC</a>)
 * @email m.makki@skylimits.tech
 * @since long time ago
 */

@RestController
@RequestMapping("/keycloak")
public class KeycloakController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('cli_user')")
    public String user() {
        return "Hello from Spring boot & Keycloak";
    }

    @GetMapping("/manager")
    @PreAuthorize("hasRole('cli_manager')")
    public String manager() {
        return "Hello from Spring boot & Keycloak - MANAGER";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('cli_admin')")
    public String admin() {
        return "Hello from Spring boot & Keycloak - ADMIN";
    }
}
