using System;
using System.Configuration;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;

namespace Infra.CrossCutting.Identity.Configuracao
{
    public class EmailService : IIdentityMessageService
    {
        
        public Task SendAsync(IdentityMessage message)
        {
            return SendMail(message);
        }

        // Implementação de e-mail manual
        private Task SendMail(IdentityMessage message)
        {
            if (ConfigurationManager.AppSettings["Internet"] == "true")
            {             
                var msg = new MailMessage();
                msg.From = new MailAddress("admin@portal.com.br", "Admin do Portal");
                msg.To.Add(new MailAddress(message.Destination));
                msg.Subject = message.Subject;
                msg.IsBodyHtml = true;
                msg.Body = message.Body;
                msg.Priority = MailPriority.High;
                msg.BodyTransferEncoding = TransferEncoding.Base64;
                msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.Body, null, MediaTypeNames.Text.Plain));
                msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(message.Body, null, MediaTypeNames.Text.Html));

                var smtpClient = new SmtpClient("smtp.gmail.com", Convert.ToInt32(587));
                smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
                var credentials = new NetworkCredential(ConfigurationManager.AppSettings["ContaDeEmail"],
                ConfigurationManager.AppSettings["SenhaEmail"]);
                smtpClient.UseDefaultCredentials = false;       
                smtpClient.Credentials = credentials;
                smtpClient.EnableSsl = true;
                smtpClient.Send(msg);
            }

            return Task.FromResult(0);
        }
        
    }
}
