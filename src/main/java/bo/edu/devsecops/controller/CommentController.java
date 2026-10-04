package bo.edu.devsecops.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    private static final String PREVIEW_TEMPLATE = "<html><body><h2>Vista previa</h2><p>%s</p></body></html>";

    @PostMapping(value = "/preview", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> preview(@RequestBody Map<String, String> body) {
        // Codificacion de salida: el comentario se muestra como texto, no se interpreta como HTML.
        String safeComment = HtmlUtils.htmlEscape(body.getOrDefault("comment", ""));
        return ResponseEntity.ok(PREVIEW_TEMPLATE.formatted(safeComment));
    }
}
