using System.Web.Mvc;
using frontend_HistorialMedico.Filters;
using HistorialMedicoUtil;

namespace frontend_HistorialMedico.Controllers
{
    public class UsuarioController : Controller
    {
        // GET: Usuario
        [SecuritySession]
        public ActionResult Index()
        {
            int irolusuario = UtlAuditoria.ObtenerTipoUsuario();
            ViewBag.GrolUsuario = irolusuario;
            //ViewBag.GImagenUsuario = UtlAuditoria.ObtenerImagenUsuario();
            return View();
        }

    }
}