using frontend_HistorialMedico.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using HistorialMedicoUtil;
namespace frontend_SoftColegio.Controllers
{
    public class HomeController : Controller
    {
        [SecuritySession]
        public ActionResult Index()
        {
            ViewBag.GrolUsuario = UtlAuditoria.ObtenerTipoUsuario();
            return View();
        }
    }
}